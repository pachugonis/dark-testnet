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

import asyncio
import asyncio.trsock
import logging
import sys
import socket
import struct
import textwrap
import time

from chutney.errors import ChutneyUnimplementedError
from chutney.Util import IPAddress
from ipaddress import IPv4Address, IPv6Address
from typeguard import check_type
from typing import Optional, Iterable, Union
from typing_extensions import assert_never

logger = logging.getLogger(__name__)

HostPortTuple = tuple[Union[str, IPv4Address, IPv6Address], int]


UNIQ_CTR = 0


def uniq(s: str) -> str:
    global UNIQ_CTR
    UNIQ_CTR += 1
    return "%s-%s" % (s, UNIQ_CTR)


def addr_to_family(
    addr: Union[str, IPAddress],
) -> Optional[socket.AddressFamily]:
    if isinstance(addr, IPv4Address):
        return socket.AF_INET
    elif isinstance(addr, IPv6Address):
        return socket.AF_INET6
    elif isinstance(addr, str):
        for family in [socket.AF_INET, socket.AF_INET6]:
            try:
                socket.inet_pton(family, addr)
                return family
            except (socket.error, OSError):
                pass
        # We get here if `addr` is a hostname.
        return None
    else:
        assert_never(addr)


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
    addr: bytes
    if isinstance(host, str):
        # hostname, to be resolved (socksv4a)
        addr = b"\x00\x00\x00\x01"
        dnsname = "%s\x00" % host
    elif isinstance(host, IPv6Address):
        raise ChutneyUnimplementedError(
            f"ipv6 address {addr_port} requires socksv5, which is unimplemented"
        )
    elif isinstance(host, IPv4Address):
        addr = host.packed
    else:
        assert_never(host)
    logger.debug("Socks 4a request to %s:%d" % (host, port))
    dnsname_enc: bytes = dnsname.encode("ascii")
    return struct.pack("!BBH", ver, cmd, port) + addr + user + dnsname_enc


class SocksError(Exception):
    def __init__(self, code: int):
        self._code = code

    def __str__(self) -> str:
        return f"Server returned code {self._code}"


async def _do_socks_client_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, server: HostPortTuple
) -> None:
    await writer.drain()
    writer.write(socks_cmd(server))
    handshake_response = await reader.readexactly(8)
    if not handshake_response.startswith(b"\x00\x5a"):
        raise SocksError(handshake_response[1])


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

    def wont_complete(self, name: str, note: str) -> None:
        """Declare that a test won't complete, if it hasn't already"""
        if self.tests[name].done():
            return
        self.failure(name)
        self.note(name, note)

    def failure_count(self) -> int:
        return self.failures

    def all_done(self) -> bool:
        return self.not_done == 0

    def status(self) -> str:
        lines = []
        for test, fut in self.tests.items():
            fut_str = f"{fut.result()}" if fut.done() else "not done"
            lines.append(f"{test}: {fut_str} ({self.teststatus.get(test)})")

        return "%s\nnot-done:%d successes:%d failures:%d" % (
            "\n".join(lines),
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

        family = addr_to_family(self._endpoint[0])
        if family is None:
            # endpoint is a hostname to be resolved.
            # Try resolving it an ipv4 address by default.
            # TODO: Maybe don't support hostnames here, and push this
            # logic/decision up to caller.
            assert isinstance(self._endpoint[0], str)
            family = socket.AF_INET

        try:
            server = await asyncio.start_server(
                _accept_cb,
                host=str(self._endpoint[0]),
                port=self._endpoint[1],
                family=family,
            )
            self._server.set_result(server)
        except BaseException as e:
            self._server.set_exception(e)
            raise
        await server.serve_forever()

    async def handle_accepted(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        newsock = writer.get_extra_info("socket")
        logger.debug("new client from %s (fd=%d)" % (peer, newsock.fileno()))
        self.tt.add_responder(reader, writer)

    async def _socket(self) -> socket.socket:
        server = await self._server
        sockets = server.sockets
        assert len(sockets) == 1, f"Unexpectedly got {len(sockets)} sockets"
        return sockets[0]

    def close(self) -> None:
        """Start closing"""
        # Clean up, and ensure we don't create the server if we haven't already.
        self._task.cancel()
        if self._server.done() and self._server.exception() is None:
            server = self._server.result()
            server.close()

    async def wait_closed(self) -> None:
        """Wait for listening socket to be closed"""
        if self._server.done() and self._server.exception() is None:
            server = self._server.result()
            await server.wait_closed()

    async def fileno(self) -> int:
        socket = await self._socket()
        return socket.fileno()


class DataSource(object):
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

    def more(self) -> bytes:
        self.sent_any = True
        if self.repetitions > 0:
            self.repetitions -= 1
            return self.data

        return b""

    def bytes_remaining(self) -> int:
        return len(self.data) * self.repetitions


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

    def bytes_remaining(self) -> int:
        return len(self.pending) + self.source.bytes_remaining()


class EchoServer(object):
    def __init__(
        self,
        tt: TrafficTester,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self.tt = tt
        self._reader = reader
        self._writer = writer
        self._run_task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        while True:
            # 64K; this is the default in asynchat.
            _BUFSIZE = 64 * 1024
            data = await self._reader.read(_BUFSIZE)
            if not data:
                break
            await self._writer.drain()
            self._writer.write(data)
        self._writer.close()
        await self._writer.wait_closed()

    def abort(self) -> None:
        """Start closing"""
        self._run_task.cancel()
        self._writer.transport.abort()
        self._writer.close()

    async def wait_closed(self) -> None:
        """Wait for close to complete"""
        await self._writer.wait_closed()


class EchoClient(object):
    def __init__(
        self,
        tt: TrafficTester,
        name: str,
        server: HostPortTuple,
        proxy: Optional[HostPortTuple] = None,
    ):
        # We'll get the reader and writer themselves asynchronously.
        loop = asyncio.get_running_loop()
        self._reader: asyncio.Future[asyncio.StreamReader] = loop.create_future()
        self._writer: asyncio.Future[asyncio.StreamWriter] = loop.create_future()

        self.name = (name,)
        self.data_source = tt.data_source.copy()
        self.proxy = proxy
        self.server = server
        self.tt = tt
        self.testname = uniq(f"{name} send-data")
        self.data_checker = DataChecker(tt.data_source.copy())
        self.testname_check = uniq(f"{name} check")
        self._run_task: asyncio.Task[None] = asyncio.create_task(self._run())

    async def _run(self) -> None:
        try:
            dest = self.proxy or self.server
            logger.debug("connecting to %r...", dest)
            try:
                reader, writer = await asyncio.open_connection(
                    host=str(dest[0]), port=dest[1]
                )
                self._reader.set_result(reader)
                self._writer.set_result(writer)
            except BaseException as e:
                self._reader.set_exception(e)
                self._writer.set_exception(e)
                raise
            if self.proxy:
                self.note("connected, sending socks handshake")
                await _do_socks_client_handshake(reader, writer, self.server)
                self.note("proxy handshake successful")
                logger.debug("successfully connected (fd=%d)" % await self.fileno())

            # Start asynchronously handling the reader and writer.
            validate_incoming_task = asyncio.create_task(self._validate_incoming())
            write_outgoing_task = asyncio.create_task(self._write_outgoing())

            # Wait for both to complete or one to throw an exception
            await asyncio.wait(
                [validate_incoming_task, write_outgoing_task],
                return_when=asyncio.FIRST_EXCEPTION,
            )
            # Close the socket, flushing any pending writes.
            writer.close()
            await writer.wait_closed()

        except Exception as e:
            for t in self.get_test_names():
                self.tt.wont_complete(t, f"Got exception: {e}")
            raise

    def enote(self, s: str) -> None:
        self.tt.tests.note(self.testname_check, s)

    def get_test_names(self) -> list[str]:
        return [self.testname, self.testname_check]

    def sent_ok(self) -> None:
        self.tt.success(self.testname)

    def note(self, s: str) -> None:
        logger.debug(f"adding note: {s}")
        self.tt.tests.note(self.testname, s)

    async def _validate_incoming(self) -> None:
        reader = await self._reader
        while True:
            # 64K; this is the default in asynchat.
            _BUFSIZE = 64 * 1024
            data = await reader.read(_BUFSIZE)
            if not data:
                # We would have already stopped reading earlier if we'd gotten
                # all the data we expected.
                self.enote("Unexpected EOF")
                self.tt.failure(self.testname_check)
                return
            self.data_checker.consume(data)
            self.enote(
                f"consumed some. remaining:{self.data_checker.bytes_remaining()}"
            )
            if self.data_checker.succeeded:
                self.enote("successful verification")
                logger.debug("successful verification")
                self.tt.success(self.testname_check)
                return
            elif self.data_checker.failed:
                logger.debug("receive comparison failed")
                self.enote("receive comparison failed")
                self.tt.failure(self.testname_check)
                return

    async def _write_outgoing(self) -> None:
        writer = await self._writer
        while True:
            data = self.data_source.more()
            if not data:
                self.note("Flushing")
                # Do *not* shut down the write-end here
                # (e.g. via `writer.write_eof`). When connected via tor, doing
                # so results in the circuit getting closed, potentially before
                # we're done reading.
                # See
                # <https://gitlab.torproject.org/tpo/core/torspec/-/issues/138>.

                # There is no straight-forward "flush all the buffered data" API
                # other than closing the socket. `StreamWriter.drain` only
                # ensures that data is flushed until some low watermark is
                # reached. So we set that watermark to 0 and *then* call
                # `drain`.
                #
                # * discussion:
                #   <https://discuss.python.org/t/completely-flushing-a-streamwriter/9621>
                # * drain:
                #   <https://docs.python.org/3/library/asyncio-stream.html#asyncio.StreamWriter.drain>
                # * set_write_buffer_limits:
                #   <https://docs.python.org/3/library/asyncio-protocol.html#asyncio.WriteTransport.set_write_buffer_limits>
                #
                # This *might* not be necessary. I suspect the framework
                # actually feeds buffered data to the kernel as quickly as the
                # kernel will take it, and waiting on `drain` is just to apply
                # back-pressure. Still, without some documented promise of that
                # behavior, let's force the issue.
                writer.transport.set_write_buffer_limits(0, 0)
                await writer.drain()
                self.note("Flushed")
                self.sent_ok()

                break
            await writer.drain()
            writer.write(data)
            self.note(f"wrote some. remaining:{self.data_source.bytes_remaining()}")

    async def _socket(self) -> asyncio.trsock.TransportSocket:
        writer = await self._writer
        s = writer.get_extra_info("socket")
        return check_type(s, asyncio.trsock.TransportSocket)

    def abort(self) -> None:
        self._run_task.cancel()
        if self._writer.done() and self._writer.exception() is None:
            writer = self._writer.result()
            writer.transport.abort()
            writer.close()

    async def wait_closed(self) -> None:
        if self._writer.done() and self._writer.exception is None:
            await self._writer.result().wait_closed()

    async def fileno(self) -> int:
        socket = await self._socket()
        assert socket is not None
        return socket.fileno()


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
    ):
        self.endpoint = endpoint
        # Don't create the listener until we start running.
        self.listener: Optional[Listener] = None
        self.timeout = timeout
        self.tests = TestSuite()
        self.data_source = DataSource(data, repetitions)
        self.responders: list[EchoServer] = []

        # In `add_client` we just store the specifications for the clients.
        # We actually create them after we start running.
        self.client_specs: list[tuple[str, HostPortTuple, Optional[HostPortTuple]]] = []
        self.clients: list[EchoClient] = []

    def add_tests(self, test_names: Iterable[str]) -> None:
        """Register tests"""
        for name in test_names:
            self.tests.add(name)

    def add_client(
        self, name: str, server: HostPortTuple, proxy: Optional[HostPortTuple] = None
    ) -> None:
        self.client_specs.append((name, server, proxy))

    def add_responder(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        sink = EchoServer(self, reader, writer)
        self.responders.append(sink)

    def success(self, name: str) -> None:
        """Declare that a single test has passed."""
        self.tests.success(name)

    def failure(self, name: str) -> None:
        """Declare that a single test has failed."""
        self.tests.failure(name)

    def wont_complete(self, name: str, note: str) -> None:
        """Declare that a test won't complete, if it hasn't already"""
        self.tests.wont_complete(name, note)

    async def _run(self) -> bool:
        # This does the real work of running the tests.

        # start listener
        self.listener = Listener(self, self.endpoint)
        logger.debug("listener fd=%d" % (await self.listener.fileno()))

        # start clients
        for cs in self.client_specs:
            source = EchoClient(self, cs[0], cs[1], cs[2])
            self.clients.append(source)
            self.add_tests(source.get_test_names())

        # periodically log status in the background
        async def _dump_status() -> None:
            start = time.time()
            while True:
                DUMP_TEST_STATUS_INTERVAL = 0.5
                await asyncio.sleep(DUMP_TEST_STATUS_INTERVAL)
                logger.debug(
                    "After %.1fs: Test status:\n%s",
                    time.time() - start,
                    textwrap.indent(self.tests.status(), "  "),
                )

        status_task = asyncio.create_task(_dump_status())
        await self.tests.wait_done()
        status_task.cancel()

        assert self.tests.all_done()
        return self.tests.failure_count() == 0

    async def _run_with_timeout(self) -> bool:
        # Inner async version of `run`. To ensure we correctly enforce the
        # timeout, any `await`s here should have a timeout or otherwise
        # ~guarantee that they won't take long.

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
        logger.info("Status:\n%s" % textwrap.indent(self.tests.status(), "  "))

        # Ensure all sockets are closed before returning.
        # We especially want to ensure that the listening socket is closed so that
        # we can retry without getting EADDRINUSE.
        #
        # shadow currently erroneously doesn't consider the listening port free
        # again until all child sockets are closed too, so we ensure those are
        # all closed too.
        # <https://github.com/shadow/shadow/issues/3563>
        #
        # TODO: Unfortunately we still get ADDRINUSE when retrying under shadow.
        for r in self.responders:
            r.abort()
            await r.wait_closed()
        for c in self.clients:
            c.abort()
            await c.wait_closed()
        if self.listener is not None:
            self.listener.close()
            await self.listener.wait_closed()

        return res

    def run(self) -> bool:
        return asyncio.run(self._run_with_timeout())


def main() -> int:
    """Test the TrafficTester by sending and receiving some data."""
    DATA = b"a foo is a bar" * 1000
    bind_to = ("localhost", int(sys.argv[1]))

    tt = TrafficTester(bind_to, DATA)
    # Don't use a proxy for self-testing, so that we avoid tor entirely
    tt.add_client("client", bind_to)
    success = tt.run()

    if success:
        return 0
    return 255


if __name__ == "__main__":
    sys.exit(main())
