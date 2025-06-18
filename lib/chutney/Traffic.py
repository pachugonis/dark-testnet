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
import logging
import sys
import socket
import struct
import time

import asyncore
import asynchat

from typing import Any, Callable, Optional, cast
from typing_extensions import override

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
        self.tests: dict[str, str] = {}
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
            self.tests[name] = "not done"
        else:
            logger.warning("... already registered!")

    def success(self, name: str) -> None:
        logger.info("Success for %s" % name)
        if self.tests[name] == "not done":
            logger.debug("Succeeded %s" % name)
            self.tests[name] = "success"
            self.not_done -= 1
            self.successes += 1
        else:
            logger.warning("... status was %s" % self.tests.get(name))

    def failure(self, name: str) -> None:
        logger.info("Failure for %s" % name)
        if self.tests[name] == "not done":
            logger.debug("Failed %s" % name)
            self.tests[name] = "failure"
            self.not_done -= 1
            self.failures += 1
        else:
            logger.warning("... status was %s" % self.tests.get(name))

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


class Listener(asyncore.dispatcher):
    "A TCP listener, binding, listening and accepting new connections."

    def __init__(self, tt: TrafficTester, endpoint: HostPortTuple):
        asyncore.dispatcher.__init__(self, map=tt.socket_map)
        self.create_socket(addr_to_family(endpoint[0]), socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(endpoint)
        self.listen(0)
        self.tt = tt

    @override
    def writable(self) -> bool:
        return False

    @override
    def handle_accept(self) -> None:
        # deprecated in python 3.2
        pair = self.accept()
        if pair is not None:
            newsock, endpoint = pair
            logger.debug(
                "new client from %s:%s (fd=%d)"
                % (endpoint[0], endpoint[1], newsock.fileno())
            )
            self.tt.add_responder(newsock)

    def fileno(self) -> int:
        assert self.socket is not None
        return self.socket.fileno()


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


class Sink(asynchat.async_chat):
    "A data sink, reading from its peer and verifying the data."

    def __init__(self, sock: socket.socket, tt: TrafficTester):
        asynchat.async_chat.__init__(self, sock, map=tt.socket_map)
        self.set_terminator(None)
        self.tt = tt
        self.data_checker = DataChecker(tt.data_source.copy())
        self.testname = uniq("recv-data")

    def get_test_names(self) -> list[str]:
        return [self.testname]

    @override
    def collect_incoming_data(self, inp: bytes) -> None:
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

    def fileno(self) -> int:
        assert self.socket is not None
        return self.socket.fileno()


class CloseSourceProducer(AsynChatProducer):
    """Helper: when this producer is returned, a source is successful."""

    def __init__(self, source: Source):
        self.source = source

    @override
    def more(self) -> bytes:
        self.source.note("Flushed")
        self.source.sent_ok()
        return b""


class Source(asynchat.async_chat):
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
        asynchat.async_chat.__init__(self, map=tt.socket_map)
        self.data_source = tt.data_source.copy()
        self.inbuf = b""
        self.proxy = proxy
        self.server = server
        self.tt = tt
        self.testname = uniq("send-data")

        self.set_terminator(None)
        dest = self.proxy or self.server
        self.create_socket(addr_to_family(dest[0]), socket.SOCK_STREAM)
        logger.debug("socket %d connecting to %r..." % (self.fileno(), dest))
        self.state = self.CONNECTING
        self.connect(dest)

    def get_test_names(self) -> list[str]:
        return [self.testname]

    def sent_ok(self) -> None:
        self.tt.success(self.testname)

    def note(self, s: str) -> None:
        self.tt.tests.note(self.testname, s)

    @override
    def handle_connect(self) -> None:
        if self.proxy:
            self.state = self.CONNECTING_THROUGH_PROXY
            self.note("connected, sending socks handshake")
            self.push(socks_cmd(self.server))
        else:
            self.state = self.CONNECTED
            self.push_output()

    @override
    def collect_incoming_data(self, data: bytes) -> None:
        self.inbuf += data
        if self.state == self.CONNECTING_THROUGH_PROXY:
            if len(self.inbuf) >= 8:
                if self.inbuf[:2] == b"\x00\x5a":
                    self.note("proxy handshake successful")
                    self.state = self.CONNECTED
                    logger.debug("successfully connected (fd=%d)" % self.fileno())
                    self.inbuf = self.inbuf[8:]
                    self.push_output()
                else:
                    logger.debug(
                        "proxy handshake failed (0x%x)! (fd=%d)"
                        % (self.inbuf[1], self.fileno())
                    )
                    self.state = self.NOT_CONNECTED
                    self.close()

    def _push_with_producer_interface(self, producer: AsynChatProducer) -> None:
        # In at least some versions of Python,
        # async_chat.push_with_producer is incorrectly annotated to require the
        # `simple_producer` type.
        # It *should* accept anything that implements the producer interface.
        # We get around this with an unchecked cast.
        self.push_with_producer(cast(asynchat.simple_producer, producer))

    def push_output(self) -> None:
        self.note("pushed output")
        self._push_with_producer_interface(self.data_source)

        self._push_with_producer_interface(CloseSourceProducer(self))

    def fileno(self) -> int:
        assert self.socket is not None
        return self.socket.fileno()


class EchoServer(asynchat.async_chat):
    def __init__(self, sock: socket.socket, tt: TrafficTester):
        asynchat.async_chat.__init__(self, sock, map=tt.socket_map)
        self.set_terminator(None)
        self.tt = tt
        self.am_closing = False

    @override
    def collect_incoming_data(self, data: bytes) -> None:
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
        self.am_closing = False

    def enote(self, s: str) -> None:
        self.tt.tests.note(self.testname_check, s)

    @override
    def get_test_names(self) -> list[str]:
        return [self.testname, self.testname_check]

    @override
    def collect_incoming_data(self, data: bytes) -> None:
        if self.state == self.CONNECTING_THROUGH_PROXY:
            Source.collect_incoming_data(self, data)
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
            [socket.socket, TrafficTester], asynchat.async_chat
        ]
        if chat_type == "Echo":
            self.client_class = EchoClient
            self.responder_class = EchoServer
        else:
            self.client_class = Source
            self.responder_class = Sink

        self.socket_map: dict[Any, Any] = {}

        self.listener = Listener(self, endpoint)
        self.timeout = timeout
        self.tests = TestSuite()
        self.data_source = DataSource(data, repetitions)

        # sanity checks
        logger.debug("listener fd=%d" % self.listener.fileno())

    def add(self, item: asynchat.async_chat) -> None:
        """Register a single item."""
        # We used to hold on to these items for their fds, but now
        # asyncore manages them for us.
        if hasattr(item, "get_test_names"):
            for name in item.get_test_names():
                self.tests.add(name)

    def add_client(
        self, server: HostPortTuple, proxy: Optional[HostPortTuple] = None
    ) -> None:
        source = self.client_class(self, server, proxy)
        self.add(source)

    def add_responder(self, socket: socket.socket) -> None:
        sink = self.responder_class(socket, self)
        self.add(sink)

    def success(self, name: str) -> None:
        """Declare that a single test has passed."""
        self.tests.success(name)

    def failure(self, name: str) -> None:
        """Declare that a single test has failed."""
        self.tests.failure(name)

    def run(self) -> bool:
        start = now = time.time()
        end = time.time() + self.timeout
        DUMP_TEST_STATUS_INTERVAL = 0.5
        dump_at = start + DUMP_TEST_STATUS_INTERVAL
        while now < end and not self.tests.all_done():
            # run only one iteration at a time, with a nice short timeout, so we
            # can actually detect completion and timeouts.
            asyncore.loop(5.0, False, self.socket_map, 1)
            now = time.time()
            if now > dump_at:
                logger.debug("Test status: %s" % self.tests.status())
                dump_at += DUMP_TEST_STATUS_INTERVAL

        logger.debug(
            "Done with run(); all_done == %s and failure_count == %s"
            % (self.tests.all_done(), self.tests.failure_count())
        )

        logger.info("Status:\n%s" % self.tests.teststatus)

        self.listener.close()

        return self.tests.all_done() and self.tests.failure_count() == 0


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
