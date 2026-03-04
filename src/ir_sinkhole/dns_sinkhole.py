"""
Minimal DNS sinkhole: intercepts all DNS queries over UDP, logs them,
and responds with 127.0.0.1 (A) or ::1 (AAAA) to prevent DNS-based
C2 tunneling (MITRE T1071.004).

No external dependencies - hand-parses the DNS wire format.
"""
import asyncio
import logging
import struct
from typing import Optional

LOG = logging.getLogger(__name__)

DNS_SINKHOLE_PORT = 15353


def _build_response(query: bytes, spoof_ip: str = "127.0.0.1") -> Optional[bytes]:
    """Build a minimal DNS response for an A or AAAA query."""
    if len(query) < 12:
        return None

    txn_id = query[:2]
    flags = struct.unpack("!H", query[2:4])[0]
    if flags & 0x8000:
        return None

    qdcount = struct.unpack("!H", query[4:6])[0]
    if qdcount < 1:
        return None

    offset = 12
    labels: list[str] = []
    while offset < len(query):
        length = query[offset]
        if length == 0:
            offset += 1
            break
        if offset + 1 + length > len(query):
            return None
        labels.append(query[offset + 1 : offset + 1 + length].decode("ascii", errors="replace"))
        offset += 1 + length

    if offset + 4 > len(query):
        return None

    qtype = struct.unpack("!H", query[offset : offset + 2])[0]
    qclass = struct.unpack("!H", query[offset + 2 : offset + 4])[0]
    domain = ".".join(labels)

    resp_flags = 0x8180
    header = txn_id + struct.pack("!HHHHH", resp_flags, qdcount, 1, 0, 0)

    question = query[12 : offset + 4]

    name_ptr = b"\xc0\x0c"
    ttl = struct.pack("!I", 60)

    if qtype == 28:  # AAAA
        rdata = b"\x00" * 15 + b"\x01"
        answer = name_ptr + struct.pack("!HH", 28, qclass) + ttl + struct.pack("!H", 16) + rdata
        LOG.info("DNS query: %s (AAAA) -> ::1", domain)
    else:  # A or anything else → A record
        parts = spoof_ip.split(".")
        rdata = bytes(int(p) for p in parts)
        answer = name_ptr + struct.pack("!HH", 1, qclass) + ttl + struct.pack("!H", 4) + rdata
        LOG.info("DNS query: %s (A) -> %s", domain, spoof_ip)

    return header + question + answer


class DnsSinkholeProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol for the DNS sinkhole."""

    def __init__(self, queries_log: Optional[list] = None):
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.queries_log = queries_log if queries_log is not None else []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self.queries_log.append({"src": addr, "raw_len": len(data)})
        response = _build_response(data)
        if response and self.transport:
            self.transport.sendto(response, addr)


async def start_dns_sinkhole(
    bind_host: str = "127.0.0.1",
    port: int = DNS_SINKHOLE_PORT,
) -> tuple[asyncio.DatagramTransport, list]:
    """Start the DNS sinkhole. Returns (transport, queries_log)."""
    queries_log: list = []
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsSinkholeProtocol(queries_log),
        local_addr=(bind_host, port),
    )
    LOG.info("DNS sinkhole listening on %s:%d (all queries → 127.0.0.1)", bind_host, port)
    return transport, queries_log
