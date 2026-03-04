"""
Sinkhole daemon: TCP listeners that replay PCAP responses or send stub to avoid
malware disconnect-triggered behaviors.
"""
import asyncio
import logging
from pathlib import Path
from typing import Optional

from .config import SinkholeConfig
from .replay import ReplayDB, build_replay_db, load_replay_db

LOG = logging.getLogger(__name__)

# Generic HTTP stub so HTTP-based C2 doesn't see connection failure
HTTP_STUB = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    remote_key: tuple[str, str],
    replay_chunks: list[bytes],
    config: SinkholeConfig,
) -> None:
    """Serve one client: replay chunks or stub."""
    peer = writer.get_extra_info("peername", "unknown")
    try:
        if replay_chunks:
            for i, chunk in enumerate(replay_chunks):
                writer.write(chunk)
                await writer.drain()
                if config.replay_chunk_delay_ms > 0:
                    await asyncio.sleep(config.replay_chunk_delay_ms / 1000.0)
            LOG.debug("Replayed %d chunk(s) for %s to %s", len(replay_chunks), remote_key, peer)
        else:
            if config.stub_http_ok:
                writer.write(HTTP_STUB)
                await writer.drain()
            if config.stub_tcp_keepalive:
                # Keep connection open until client closes (malware may hold socket)
                try:
                    while True:
                        _ = await asyncio.wait_for(reader.read(8192), timeout=300.0)
                        if not _:
                            break
                except asyncio.TimeoutError:
                    pass
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _make_handler(
    remote_key: tuple[str, str],
    replay_chunks: list[bytes],
    config: SinkholeConfig,
):
    def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        return _handle_client(reader, writer, remote_key, replay_chunks, config)
    return handler


class SinkholeServer:
    """Manages asyncio TCP servers for each redirected (remote_ip, remote_port)."""

    def __init__(
        self,
        endpoints: list[tuple[str, str]],
        replay_db: ReplayDB,
        config: SinkholeConfig,
        port_start: int = 19000,
    ):
        self.endpoints = endpoints
        self.replay_db = replay_db
        self.config = config
        self.port_start = port_start
        self._servers: list[asyncio.Server] = []
        self._port_map: dict[tuple[str, str], int] = {
            (ip, port): port_start + i for i, (ip, port) in enumerate(endpoints)
        }

    def get_port_map(self) -> dict[tuple[str, str], int]:
        """(remote_ip, remote_port) -> local_port for firewall DNAT."""
        return dict(self._port_map)

    async def start(self) -> None:
        """Start one TCP server per endpoint."""
        host = self.config.bind_host
        for i, (remote_ip, remote_port) in enumerate(self.endpoints):
            local_port = self.port_start + i
            key = (remote_ip, remote_port)
            chunks = self.replay_db.get(key, [])
            handler = _make_handler(key, chunks, self.config)
            server = await asyncio.start_server(handler, host, local_port)
            self._servers.append(server)
            LOG.info("Sinkhole listening %s:%d -> replay %s:%s (%d chunks)",
                     host, local_port, remote_ip, remote_port, len(chunks))
        if not self._servers:
            LOG.warning("No sinkhole servers started (no endpoints)")
            return
        # Run all servers until cancelled
        await asyncio.gather(*[s.serve_forever() for s in self._servers])

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
            await s.wait_closed()
        self._servers.clear()


def create_sinkhole(
    endpoints: list[tuple[str, str]],
    replay_db: ReplayDB,
    config: SinkholeConfig,
    port_start: int = 19000,
) -> SinkholeServer:
    return SinkholeServer(endpoints, replay_db, config, port_start)


async def run_sinkhole_forever(server: SinkholeServer) -> None:
    """Run sinkhole until cancelled. Use server.get_port_map() before starting for firewall."""
    await server.start()
