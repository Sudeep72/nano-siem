"""
listener.py — Network Log Listeners

Provides async UDP and TCP syslog listeners plus a JSON-over-TCP listener.
Each listener puts raw bytes onto a shared asyncio.Queue which the main
pipeline consumes. Keeping listeners separate from parsing means the queue
never blocks on parsing logic.

Architecture:
  UDPSyslogListener   → queue  ─┐
  TCPSyslogListener   → queue  ─┼─► pipeline consumer (main.py)
  TCPJsonListener     → queue  ─┘

Usage (from main.py):
    queue = asyncio.Queue(maxsize=10_000)
    listeners = [
        UDPSyslogListener("0.0.0.0", 5140, queue),
        TCPJsonListener("0.0.0.0", 5141, queue),
    ]
    async with asyncio.TaskGroup() as tg:
        for l in listeners:
            tg.create_task(l.start())
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Max UDP datagram size — 64KB is the theoretical max but 4096 covers 99% of logs
_UDP_BUFFER = 65535
# Max bytes to read per TCP line (protects against OOM on malformed clients)
_TCP_LINE_LIMIT = 65535


@dataclass
class RawMessage:
    """
    Container for a raw log message arriving from the network.
    Carries the raw bytes plus metadata about where it came from.
    """
    data: bytes
    source_addr: tuple[str, int]  # (host, port)
    transport: str                 # "udp" | "tcp_syslog" | "tcp_json"


# ── UDP Syslog Listener ────────────────────────────────────────────────────────

class _UDPProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol handler — one datagram = one log message."""

    def __init__(self, queue: asyncio.Queue[RawMessage], host: str, port: int) -> None:
        self._queue = queue
        self._host = host
        self._port = port

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.info(f"UDP syslog listener started on {self._host}:{self._port}")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        msg = RawMessage(data=data, source_addr=addr, transport="udp")
        try:
            self._queue.put_nowait(msg)
        except asyncio.QueueFull:
            logger.warning("Ingestion queue full — dropping UDP datagram from %s", addr[0])

    def error_received(self, exc: Exception) -> None:
        logger.error("UDP listener error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("UDP connection lost: %s", exc)


class UDPSyslogListener:
    """Listens for syslog messages over UDP (RFC 3164 / RFC 5424)."""

    def __init__(self, host: str, port: int, queue: asyncio.Queue[RawMessage]) -> None:
        self.host = host
        self.port = port
        self._queue = queue

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._queue, self.host, self.port),
            local_addr=(self.host, self.port),
        )
        try:
            # Run forever — cancelled by TaskGroup shutdown
            await asyncio.Future()
        finally:
            transport.close()


# ── TCP Syslog Listener ────────────────────────────────────────────────────────

class TCPSyslogListener:
    """
    Listens for syslog over TCP.
    RFC 6587 specifies two framing methods:
      1. Octet-counting: '<length> <message>'
      2. Non-transparent (newline delimited) — we support this as it's most common

    Each newline-terminated message is enqueued as one RawMessage.
    """

    def __init__(self, host: str, port: int, queue: asyncio.Queue[RawMessage]) -> None:
        self.host = host
        self.port = port
        self._queue = queue

    async def start(self) -> None:
        server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"TCP syslog listener started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername", ("unknown", 0))
        logger.debug("TCP syslog connection from %s:%s", *addr)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=60.0
                    )
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                line = line[:_TCP_LINE_LIMIT]
                msg = RawMessage(
                    data=line.rstrip(b"\n\r"),
                    source_addr=addr,
                    transport="tcp_syslog",
                )
                try:
                    self._queue.put_nowait(msg)
                except asyncio.QueueFull:
                    logger.warning("Queue full — dropping TCP syslog line from %s", addr[0])
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("TCP syslog connection closed from %s:%s", *addr)


# ── TCP JSON Listener ──────────────────────────────────────────────────────────

class TCPJsonListener:
    """
    Listens for newline-delimited JSON log entries over TCP.
    Each line must be a complete JSON object.
    Compatible with filebeat, fluentd, logstash JSON output.
    """

    def __init__(self, host: str, port: int, queue: asyncio.Queue[RawMessage]) -> None:
        self.host = host
        self.port = port
        self._queue = queue

    async def start(self) -> None:
        server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"TCP JSON listener started on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername", ("unknown", 0))
        logger.debug("TCP JSON connection from %s:%s", *addr)
        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=60.0
                    )
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                line = line[:_TCP_LINE_LIMIT]
                stripped = line.strip()
                if not stripped:
                    continue
                msg = RawMessage(
                    data=stripped,
                    source_addr=addr,
                    transport="tcp_json",
                )
                try:
                    self._queue.put_nowait(msg)
                except asyncio.QueueFull:
                    logger.warning("Queue full — dropping JSON line from %s", addr[0])
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ── File tail listener (bonus — for local log file ingestion) ─────────────────

class FileTailListener:
    """
    Tails a log file and enqueues new lines as they're written.
    Useful for ingesting /var/log/auth.log, /var/log/syslog, etc. directly
    without needing a network forwarder.

    Implements a simple poll-based tail (checks every `interval` seconds).
    """

    def __init__(
        self,
        path: str,
        queue: asyncio.Queue[RawMessage],
        interval: float = 0.5,
        seek_to_end: bool = True,
    ) -> None:
        self.path = path
        self._queue = queue
        self._interval = interval
        self._seek_to_end = seek_to_end

    async def start(self) -> None:
        logger.info("File tail listener started: %s", self.path)
        try:
            with open(self.path, "rb") as f:
                if self._seek_to_end:
                    f.seek(0, 2)  # seek to end
                while True:
                    line = f.readline()
                    if line:
                        line = line[:_TCP_LINE_LIMIT]
                        msg = RawMessage(
                            data=line.rstrip(b"\n\r"),
                            source_addr=("localhost", 0),
                            transport="file",
                        )
                        try:
                            self._queue.put_nowait(msg)
                        except asyncio.QueueFull:
                            logger.warning("Queue full — dropping file line")
                    else:
                        await asyncio.sleep(self._interval)
        except FileNotFoundError:
            logger.error("File not found: %s", self.path)
        except asyncio.CancelledError:
            logger.info("File tail listener stopped: %s", self.path)
