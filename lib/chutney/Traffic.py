#!/usr/bin/env python
#
# Copyright 2013 The Tor Project
#
# You may do anything with this work that copyright law would normally
# restrict, so long as you retain the above notice(s) and this license
# in all redistributed copies and derived works.  There is no warranty.

# Do select/read/write for binding to a port, connecting to it and
# write, read what's written and verify it. You can connect over a
# SOCKS proxy (like Tor).
#
# You can create a TrafficTester and give it an IP address/host and
# port to bind to. If a Source is created and added to the
# TrafficTester, it will connect to the address/port it was given at
# instantiation and send its data. A Source can be configured to
# connect over a SOCKS proxy. When everything is set up, you can
# invoke TrafficTester.run() to start running. The TrafficTester will
# accept the incoming connection and read from it, verifying the data.
#
# For example code, see main() below.

# [pep 0536](https://peps.python.org/pep-0563/) - Lazy annotation eval via
# stringification.
from __future__ import annotations

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import abc
import asyncio
import logging
import sys
import socket
import struct
import time

from abc import abstractmethod
from typing import Callable, Optional, cast, Coroutine
from typing_extensions import override, final

logger = logging.getLogger(__name__)

HostPortTuple = tuple[str, int]


UNIQ_CTR = 0


def uniq(s: str) -> str:
    global UNIQ_CTR
    UNIQ_CTR += 1
    return "%s-%s" % (s, UNIQ_CTR)


def addr_to_family(addr: str) -> socket.AddressFamily:
    for family in [socket.AF_INET, socket.AF_INET6]:
        try:
            socket.inet_pton(family, addr)
            return family
        except (socket.error, OSError):
            pass

    # We get here e.g. if `addr` is a hostname. Default to AF_INET.
    return socket.AF_INET


def socks_cmd(addr_port: HostPortTuple) -> bytes:
    """
    Return a SOCKS command for connecting to addr_port.

    SOCKSv4: https://en.wikipedia.org/wiki/SOCKS#Protocol
    SOCKSv5: RFC1928, RFC1929
    """
    ver = 4  # Only SOCKSv4 for now.
    cmd = 1  # Stream connection.
    user = b"\x00"
    dnsname = ""
    host, port = addr_port
    try:
        addr = socket.inet_aton(host)
    except socket.error:
        addr = b"\x00\x00\x00\x01"
        dnsname = "%s\x00" % host
    logger.debug("Socks 4a request to %s:%d" % (host, port))
    dnsname_enc: bytes = dnsname.encode("ascii")
    return struct.pack("!BBH", ver, cmd, port) + addr + user + dnsname_enc


class TestSuite(object):
    """Keep a tab on how many tests are pending, how many have failed
    and how many have succeeded."""

    def __init__(self) -> None:
        self.tests: dict[str, asyncio.Future[str]] = {}
        self.not_done = 0
        self.successes = 0
        self.failures = 0
        self.teststatus: dict[str, str] = {}

    def note(self, testname: str, status: str) -> None:
        self.teststatus[testname] = status

    def add(self, name: str) -> None:
        logger.info("Registering %s" % name)
        if name not in self.tests:
            logger.debug("Registering %s" % name)
            self.not_done += 1
            self.tests[name] = asyncio.get_running_loop().create_future()
        else:
            logger.warning("... already registered!")

    def success(self, name: str) -> None:
        logger.info("Success for %s" % name)
        self.tests[name].set_result("success")
        logger.debug("Succeeded %s" % name)
        self.not_done -= 1
        self.successes += 1

    def failure(self, name: str) -> None:
        logger.info("Failure for %s" % name)
        self.tests[name].set_result("failure")
        self.not_done -= 1
        self.failures += 1

    def failure_count(self) -> int:
        return self.failures

    def all_done(self) -> bool:
        return self.not_done == 0

    def status(self) -> str:
        return "%s: %d/%d/%d" % (
            self.tests,
            self.not_done,
            self.successes,
            self.failures,
        )

    async def wait_done(self) -> None:
        await asyncio.wait(self.tests.values())


class Listener(object):
    "A TCP listener, binding, listening and accepting new connections."

    def __init__(self, tt: TrafficTester, endpoint: HostPortTuple):
        self.tt = tt
        self._endpoint = endpoint
        loop = asyncio.get_running_loop()
        self._server: asyncio.Future[asyncio.Server] = loop.create_future()
        self._task: asyncio.Task[None] = asyncio.create_task(self._run())

    async def _run(self) -> None:
        async def _accept_cb(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await self.handle_accepted(reader, writer)

        try:
            server = await asyncio.start_server(
                _accept_cb,
                host=self._endpoint[0],
                port=self._endpoint[1],
                family=addr_to_family(self._endpoint[0]),
            )
            self._server.set_result(server)
        except Exception as e:
            self._server.set_exception(e)
            raise
        await server.serve_forever()

    @property
    async def socket(self) -> socket.socket:
        server = await self._server
        sockets = server.sockets
        assert len(sockets) == 1, f"Unexpectedly got {len(sockets)} sockets"
        return sockets[0]

    def close(self) -> None:
        """Start closing"""
        # Clean up, and ensure we don't create the server if we haven't already.
        self._task.cancel()
        if self._server.done():
            server = self._server.result()
            server.close()

    async def wait_closed(self) -> None:
        """Wait for close to complete"""
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        if self._server.done():
            server = self._server.result()
            await server.wait_closed()

    async def handle_accepted(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        newsock = writer.get_extra_info("socket")
        logger.debug("new client from %s (fd=%d)" % (peer, newsock.fileno()))
        self.tt.add_responder(reader, writer)

    async def fileno(self) -> int:
        socket = await self.socket
        return socket.fileno()


class AsynChatProducer(abc.ABC):
    """A Producer as defined in the AsynChat documentation."""

    @abc.abstractmethod
    def more(self) -> bytes: ...

    """Produce some bytes.

    From <https://docs.python.org/3.11/library/asynchat.html>:
    "A producer need have only one method, more(), which should return data to
    be transmitted on the channel. The producer indicates exhaustion (i.e. that
    it contains no more data) by having its more() method return the empty bytes
    object."
    """


class DataSource(AsynChatProducer):
    """A data source generates some number of bytes of data, and then
    returns None.

    For convenience, it conforms to the 'producer' api.
    """

    def __init__(self, data: bytes, repetitions: int = 1):
        self.data = data
        self.repetitions = repetitions
        self.sent_any = False

    def copy(self) -> DataSource:
        assert not self.sent_any
        return DataSource(self.data, self.repetitions)

    @override
    def more(self) -> bytes:
        self.sent_any = True
        if self.repetitions > 0:
            self.repetitions -= 1
            return self.data

        return b""


class DataChecker(object):
    """A data checker verifies its input against bytes in a stream."""

    def __init__(self, source: DataSource):
        self.source = source
        self.pending: bytes = self.source.more()
        self.succeeded = False
        self.failed = False

    def consume(self, inp: bytes) -> None:
        if self.failed:
            return
        if self.succeeded and len(inp):
            self.succeeded = False
            self.failed = True
            return

        while len(inp):
            n = min(len(inp), len(self.pending))
            if inp[:n] != self.pending[:n]:
                self.failed = True
                return
            inp = inp[n:]
            self.pending = self.pending[n:]
            if not self.pending:
                self.pending = self.source.more()

                if len(self.pending) == 0:
                    if len(inp):
                        self.failed = True
                    else:
                        self.succeeded = True
                    return


class AsyncioChat(object):
    "asyncio-based adapter for asynchat.async_chat"

    # 64K; this is the default in asynchat.
    _BUFSIZE = 64 * 1024 * 1024

    def __init__(
        self,
        reader_writer: Coroutine[
            None, None, tuple[asyncio.StreamReader, asyncio.StreamWriter]
        ],
    ) -> None:
        # We take `reader_writer` as a coroutine to facilitate client-connection subclasses.

        # We'll get the reader and writer themselves asynchronously.
        loop = asyncio.get_running_loop()
        self._reader: asyncio.Future[asyncio.StreamReader] = loop.create_future()
        self._writer: asyncio.Future[asyncio.StreamWriter] = loop.create_future()

        # After connecting we'll start additional tasks to do the reading and writing.
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._writer_task: Optional[asyncio.Task[None]] = None

        # We wrap `reader_writer` in our own coroutine so that we can call
        # `handle_connect` when it completes.
        async def _connect() -> None:
            try:
                reader, writer = await reader_writer
                self._reader.set_result(reader)
                self._writer.set_result(writer)
            except Exception as e:
                self._reader.set_exception(e)
                self._writer.set_exception(e)
                raise
            # Call the connection callback first.
            await self.handle_connect()
            # Start asynchronously handling the reader and writer.
            assert self._reader_task is None
            self._reader_task = asyncio.create_task(self._reader_closure())
            assert self._writer_task is None
            self._writer_task = asyncio.create_task(self._writer_closure())

        self._connect_task: asyncio.Task[None] = asyncio.create_task(_connect())
        self._producers: asyncio.Queue[Optional[AsynChatProducer]] = asyncio.Queue()

    @final
    async def _reader_closure(self) -> None:
        reader = await self._reader
        while True:
            data = await reader.read(AsyncioChat._BUFSIZE)
            if not data:
                break
            await self.collect_incoming_data(data)

    @final
    async def _writer_closure(self) -> None:
        writer = await self._writer
        while True:
            # Wait until we have something to write.
            # We're relying on no threading being in use to not have races
            # between `_producers_ready` and `_producers`.
            producer = await self._producers.get()
            if producer is None:
                writer.write_eof()
                break
            while True:
                # Get more data
                data = producer.more()
                if not data:
                    # this producer is exhausted
                    break
                # Wait until writer is ready for more data
                await writer.drain()
                writer.write(data)

    @final
    def push_with_producer(self, producer: AsynChatProducer) -> None:
        self._producers.put_nowait(producer)

    @final
    def push(self, data: bytes) -> None:
        self.push_with_producer(DataSource(data))

    @final
    @property
    async def socket(self) -> socket.socket:
        writer = await self._writer
        s = writer.get_extra_info("socket")
        # The documentation claims we should get a socket.socket here, but we
        # actually only get an internal type that *acts* like one.
        # Sanity-check that we got something socket-like, and return it.
        assert hasattr(s, 'fileno')
        return cast(socket.socket, s)

    @final
    def close(self) -> None:
        self._connect_task.cancel()
        if self._reader_task is not None:
            self._reader_task.cancel()
        if self._writer_task is not None:
            self._writer_task.cancel()
        if self._writer.done():
            self._writer.result().close()

    @final
    async def wait_closed(self) -> None:
        try:
            await self._connect_task
        except asyncio.CancelledError:
            pass
        if self._reader_task is not None:
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._writer_task is not None:
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
        if self._writer.done():
            await self._writer.result().wait_closed()

    async def handle_connect(self) -> None:
        """Called when the connection is ready"""
        pass

    @abstractmethod
    async def collect_incoming_data(self, inp: bytes) -> None: ...

    @final
    async def fileno(self) -> int:
        socket = await self.socket
        assert socket is not None
        return socket.fileno()


class Sink(AsyncioChat):
    "A data sink, reading from its peer and verifying the data."

    def __init__(
        self,
        tt: TrafficTester,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        async def _reader_writer() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return (reader, writer)

        AsyncioChat.__init__(self, _reader_writer())
        self.tt = tt
        self.data_checker = DataChecker(tt.data_source.copy())
        self.testname = uniq("recv-data")

    def get_test_names(self) -> list[str]:
        return [self.testname]

    @override
    async def collect_incoming_data(self, inp: bytes) -> None:
        # shortcut read when we don't ever expect any data

        logger.debug("successfully received (bytes=%d)" % len(inp))
        self.data_checker.consume(inp)
        if self.data_checker.succeeded:
            logger.debug("successful verification")
            self.close()
            self.tt.success(self.testname)
        elif self.data_checker.failed:
            logger.debug("receive comparison failed")
            self.tt.failure(self.testname)
            self.close()


class CloseSourceProducer(AsynChatProducer):
    """Helper: when this producer is returned, a source is successful."""

    def __init__(self, source: Source):
        self.source = source

    @override
    def more(self) -> bytes:
        self.source.note("Flushed")
        self.source.sent_ok()
        return b""


class Source(AsyncioChat):
    """A data source, connecting to a TCP server, optionally over a
    SOCKS proxy, sending data."""

    NOT_CONNECTED = 0
    CONNECTING = 1
    CONNECTING_THROUGH_PROXY = 2
    CONNECTED = 5

    def __init__(
        self,
        tt: TrafficTester,
        server: HostPortTuple,
        proxy: Optional[HostPortTuple] = None,
    ):
        async def _connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            dest = proxy or server
            logger.debug("connecting to %r...", dest)
            return await asyncio.open_connection(host=dest[0], port=dest[1])

        AsyncioChat.__init__(self, _connect())
        self.data_source = tt.data_source.copy()
        self.inbuf = b""
        self.proxy = proxy
        self.server = server
        self.tt = tt
        self.testname = uniq("send-data")
        self.state = self.CONNECTING

    def get_test_names(self) -> list[str]:
        return [self.testname]

    def sent_ok(self) -> None:
        self.tt.success(self.testname)

    def note(self, s: str) -> None:
        logger.debug(f"adding note: {s}")
        self.tt.tests.note(self.testname, s)

    @override
    async def handle_connect(self) -> None:
        if self.proxy:
            self.state = self.CONNECTING_THROUGH_PROXY
            self.note("connected, sending socks handshake")
            self.push(socks_cmd(self.server))
        else:
            self.state = self.CONNECTED
            self.push_output()

    @override
    async def collect_incoming_data(self, data: bytes) -> None:
        logger.debug(f"received {len(data)} bytes")
        self.inbuf += data
        if self.state == self.CONNECTING_THROUGH_PROXY:
            if len(self.inbuf) >= 8:
                if self.inbuf[:2] == b"\x00\x5a":
                    self.note("proxy handshake successful")
                    self.state = self.CONNECTED
                    logger.debug("successfully connected (fd=%d)" % await self.fileno())
                    self.inbuf = self.inbuf[8:]
                    self.push_output()
                else:
                    logger.debug(
                        "proxy handshake failed (0x%x)! (fd=%d)"
                        % (self.inbuf[1], await self.fileno())
                    )
                    self.state = self.NOT_CONNECTED
                    self.close()

    def push_output(self) -> None:
        self.note("pushed output")
        self.push_with_producer(self.data_source)
        self.push_with_producer(CloseSourceProducer(self))


class EchoServer(AsyncioChat):
    def __init__(
        self,
        tt: TrafficTester,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        async def _reader_writer() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            return (reader, writer)

        AsyncioChat.__init__(self, _reader_writer())
        self.tt = tt

    @override
    async def collect_incoming_data(self, data: bytes) -> None:
        self.push(data)


class EchoClient(Source):
    def __init__(
        self,
        tt: TrafficTester,
        server: HostPortTuple,
        proxy: Optional[HostPortTuple] = None,
    ):
        Source.__init__(self, tt, server, proxy)
        self.data_checker = DataChecker(tt.data_source.copy())
        self.testname_check = uniq("check")

    def enote(self, s: str) -> None:
        self.tt.tests.note(self.testname_check, s)

    @override
    def get_test_names(self) -> list[str]:
        return [self.testname, self.testname_check]

    @override
    async def collect_incoming_data(self, data: bytes) -> None:
        if self.state == self.CONNECTING_THROUGH_PROXY:
            await Source.collect_incoming_data(self, data)
            if self.state == self.CONNECTING_THROUGH_PROXY:
                return
            data = self.inbuf
            self.inbuf = b""

        self.data_checker.consume(data)
        self.enote("consumed some")

        if self.data_checker.succeeded:
            self.enote("successful verification")
            logger.debug("successful verification")
            self.close()
            self.tt.success(self.testname_check)
        elif self.data_checker.failed:
            logger.debug("receive comparison failed")
            self.tt.failure(self.testname_check)
            self.close()


class TrafficTester(object):
    """
    Hang on select.select() and dispatch to Sources and Sinks.
    Time out after self.timeout seconds.
    Keep track of successful and failed data verification using a
    TestSuite.
    Return True if all tests succeed, else False.
    """

    def __init__(
        self,
        endpoint: HostPortTuple,
        data: bytes = b"",
        timeout: float = 3.0,
        repetitions: int = 1,
        # TODO make this an enum?
        chat_type: str = "Echo",
    ):
        self.client_class: Callable[
            [TrafficTester, HostPortTuple, Optional[HostPortTuple]], Source
        ]
        self.responder_class: Callable[
            [TrafficTester, asyncio.StreamReader, asyncio.StreamWriter], AsyncioChat
        ]
        if chat_type == "Echo":
            self.client_class = EchoClient
            self.responder_class = EchoServer
        else:
            self.client_class = Source
            self.responder_class = Sink

        self.endpoint = endpoint
        # Don't create the listener until we start running.
        self.listener: Optional[Listener] = None
        self.timeout = timeout
        self.tests = TestSuite()
        self.data_source = DataSource(data, repetitions)
        self.responders: list[AsyncioChat] = []

        # In `add_client` we just store the specifications for the clients.
        # We actually create them after we start running.
        self.client_specs: list[tuple[HostPortTuple, Optional[HostPortTuple]]] = []
        self.clients: list[Source] = []

    def add(self, item: AsyncioChat) -> None:
        """Register a single item."""
        if hasattr(item, "get_test_names"):
            for name in item.get_test_names():
                self.tests.add(name)

    def add_client(
        self, server: HostPortTuple, proxy: Optional[HostPortTuple] = None
    ) -> None:
        self.client_specs.append((server, proxy))

    def add_responder(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        sink = self.responder_class(self, reader, writer)
        self.responders.append(sink)
        self.add(sink)

    def success(self, name: str) -> None:
        """Declare that a single test has passed."""
        self.tests.success(name)

    def failure(self, name: str) -> None:
        """Declare that a single test has failed."""
        self.tests.failure(name)

    async def _run(self) -> bool:
        # This does the real work of running the tests.

        # start listener
        self.listener = Listener(self, self.endpoint)
        logger.debug("listener fd=%d" % (await self.listener.fileno()))

        # start clients
        for cs in self.client_specs:
            source = self.client_class(self, cs[0], cs[1])
            self.clients.append(source)
            self.add(source)

        # periodically log status in the background
        async def _dump_status() -> None:
            start = time.time()
            while True:
                DUMP_TEST_STATUS_INTERVAL = 0.5
                await asyncio.sleep(DUMP_TEST_STATUS_INTERVAL)
                logger.debug(
                    "After %.1fs: Test status: %s",
                    time.time() - start,
                    self.tests.status(),
                )

        status_task = asyncio.create_task(_dump_status())
        await self.tests.wait_done()
        status_task.cancel()

        assert self.tests.all_done()
        return self.tests.failure_count() == 0

    async def _run_with_timeout(self) -> bool:
        # Inner async version of `run`. To ensure we correctly enforce the timeout,
        # there should only be a single `await` in this function, for
        # `asyncio.wait_for`, which takes a timeout.

        # In case self._run doesn't complete, we should always return failure.
        # e.g. if instead we checked `self.tests.failure_count()` ourselves
        # here, we might mistakenly report success if `self._run`` timed out
        # before it had finished adding all of the tests.
        res = False

        try:
            res = await asyncio.wait_for(self._run(), self.timeout)
        except asyncio.TimeoutError:
            logger.info("Timed out")
        logger.debug(
            "Done with run(); all_done == %s and failure_count == %s"
            % (self.tests.all_done(), self.tests.failure_count())
        )
        logger.info("Status:\n%s" % self.tests.teststatus)
        return res

    def run(self) -> bool:
        return asyncio.run(self._run_with_timeout())


def main() -> int:
    """Test the TrafficTester by sending and receiving some data."""
    DATA = b"a foo is a bar" * 1000
    bind_to = ("localhost", int(sys.argv[1]))

    tt = TrafficTester(bind_to, DATA)
    # Don't use a proxy for self-testing, so that we avoid tor entirely
    tt.add_client(bind_to)
    success = tt.run()

    if success:
        return 0
    return 255


if __name__ == "__main__":
    sys.exit(main())
