"""
Connection and traffic capture: poll active TCP connections (ss/conntrack)
and optionally run tshark for PCAP replay.
"""
import json
import logging
import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .config import CaptureConfig

LOG = logging.getLogger(__name__)

# (local_ip, local_port, remote_ip, remote_port) -> list of timestamps
ConnectionKey = tuple[str, str, str, str]
ConnectionsSnapshot = list[dict[str, Any]]


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, "", str(e)


def _parse_ss_tcp(output: str) -> ConnectionsSnapshot:
    """Parse 'ss -tunap' (or 'ss -tnap') for established TCP."""
    rows: ConnectionsSnapshot = []
    # State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    for line in output.strip().splitlines():
        if not line.strip():
            continue
        # ESTAB  0  0  192.168.1.5:45678  66.235.175.117:1244  users:(("node",pid=1234,fd=5))
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        if state != "ESTAB":
            continue
        try:
            local = parts[3]  # ip:port
            remote = parts[4]
        except IndexError:
            continue
        if ":" not in local or ":" not in remote:
            continue
        local_ip, _, local_port = local.rpartition(":")
        remote_ip, _, remote_port = remote.rpartition(":")
        pid = None
        for p in parts[5:]:
            m = re.search(r"pid=(\d+)", p)
            if m:
                pid = int(m.group(1))
                break
        rows.append({
            "local_ip": local_ip or "*",
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
        })
    return rows


def _parse_conntrack(output: str) -> ConnectionsSnapshot:
    """Parse 'conntrack -L' for IPv4 TCP."""
    rows = []
    # conntrack v1.4.3: tcp 6 431996 ESTABLISHED src=10.0.0.2 dst=66.235.175.117 sport=45678 dport=1244 ...
    for line in output.strip().splitlines():
        if " ESTABLISHED " not in line or "src=" not in line:
            continue
        src = re.search(r"\ssrc=([^\s]+)\s", line)
        dst = re.search(r"\sdst=([^\s]+)\s", line)
        sport = re.search(r"\ssport=(\d+)\s", line)
        dport = re.search(r"\sdport=(\d+)\s", line)
        if not all([src, dst, sport, dport]):
            continue
        # From host view: we are origin, so local=src, remote=dst for outbound
        rows.append({
            "local_ip": src.group(1),
            "local_port": sport.group(1),
            "remote_ip": dst.group(1),
            "remote_port": dport.group(1),
            "state": "ESTABLISHED",
            "pid": None,
        })
    return rows


def get_active_tcp_connections() -> ConnectionsSnapshot:
    """Return current TCP connections (outbound preferred). Prefer ss, fallback conntrack."""
    code, out, _ = _run(["ss", "-tnap"])
    if code == 0 and out:
        return _parse_ss_tcp(out)
    code, out, _ = _run(["conntrack", "-L"])
    if code == 0 and out:
        return _parse_conntrack(out)
    return []


def unique_remote_endpoints(connections: ConnectionsSnapshot) -> list[tuple[str, str]]:
    """Unique (remote_ip, remote_port) from connections."""
    seen: set[tuple[str, str]] = set()
    out = []
    for c in connections:
        key = (c["remote_ip"], c["remote_port"])
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


class TsharkCapture:
    """Run tshark in background and stop on demand."""

    def __init__(self, interface: str, pcap_path: Path, capture_filter: str = "tcp"):
        self.interface = interface
        self.pcap_path = pcap_path
        self.capture_filter = capture_filter
        self._process: subprocess.Popen | None = None

    def start(self) -> None:
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "tshark",
            "-i", self.interface,
            "-w", str(self.pcap_path),
            "-f", self.capture_filter,
        ]
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        LOG.info("tshark started PID=%s writing to %s", self._process.pid, self.pcap_path)

    def stop(self) -> None:
        if self._process is None:
            return
        self._process.send_signal(signal.SIGTERM)
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
        err = (self._process.stderr and self._process.stderr.read()) or b""
        if err:
            LOG.debug("tshark stderr: %s", err.decode(errors="replace"))
        self._process = None


def run_capture(config: CaptureConfig, stop_event: Optional[Any] = None) -> Path:
    """
    Run capture for config.duration_seconds (or until stop_event is set).
    Writes connections_*.json periodically and optionally runs tshark.
    Returns output_dir.
    """
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    connections_log = output_dir / "connections.jsonl"
    pcap_path = output_dir / "capture.pcap" if config.run_tshark else None

    tshark: TsharkCapture | None = None
    if config.run_tshark and pcap_path is not None:
        tshark = TsharkCapture(
            config.interface,
            pcap_path,
            config.tshark_capture_filter,
        )
        tshark.start()

    start = time.monotonic()
    last_snapshot: ConnectionsSnapshot = []
    try:
        while True:
            elapsed = time.monotonic() - start
            if elapsed >= config.duration_seconds:
                break
            if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
                break

            snapshot = get_active_tcp_connections()
            if snapshot:
                line = json.dumps({
                    "elapsed_seconds": round(elapsed, 1),
                    "count": len(snapshot),
                    "connections": snapshot,
                }) + "\n"
                with open(connections_log, "a") as f:
                    f.write(line)
                last_snapshot = snapshot

            time.sleep(config.poll_interval_seconds)
    finally:
        if tshark is not None:
            tshark.stop()

    # Write final unique endpoints for contain phase
    endpoints = unique_remote_endpoints(last_snapshot) if last_snapshot else []
    endpoints_file = output_dir / "remote_endpoints.json"
    with open(endpoints_file, "w") as f:
        json.dump([{"ip": ip, "port": port} for ip, port in endpoints], f, indent=2)
    LOG.info("Capture finished. Endpoints: %s", endpoints)

    return output_dir
