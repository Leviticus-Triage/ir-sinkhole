"""
IR Sinkhole CLI: capture, contain, stop.
"""
import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from .capture import get_active_tcp_connections, run_capture, unique_remote_endpoints
from .config import CaptureConfig, FirewallConfig, SinkholeConfig
from .dns_sinkhole import DNS_SINKHOLE_PORT, start_dns_sinkhole
from .firewall import apply_firewall, flush_conntrack, nftables_available, remove_firewall, save_rules_to_file
from .replay import build_replay_db
from .sinkhole import create_sinkhole

LOG = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = Path("/var/lib/ir-sinkhole")
PID_FILE = Path("/var/run/ir-sinkhole.pid")


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _require_root() -> None:
    if os.geteuid() != 0:
        print("error: root required for capture and containment", file=sys.stderr)
        sys.exit(1)


def cmd_status(_args: argparse.Namespace) -> int:
    """Show current connections and whether containment is active."""
    conns = get_active_tcp_connections()
    endpoints = unique_remote_endpoints(conns)
    print("Active TCP connections:", len(conns))
    print("Unique remote endpoints:", len(endpoints))
    for ip, port in endpoints:
        print(f"  {ip}:{port}")
    if PID_FILE.exists():
        pid = PID_FILE.read_text().strip()
        print("Containment: running (PID %s)" % pid)
    else:
        print("Containment: not running")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Run capture for duration, write connections + optional pcap."""
    _require_root()
    out = Path(args.output_dir)
    duration = _parse_duration(args.duration)
    config = CaptureConfig(
        duration_seconds=duration,
        interface=args.interface,
        output_dir=out,
        poll_interval_seconds=args.poll_interval,
        run_tshark=args.tshark,
        tshark_capture_filter=args.tshark_filter or "tcp",
    )
    print("Capture for %d s on %s, output %s" % (config.duration_seconds, config.interface, out))
    run_capture(config)
    print("Done. Remote endpoints written to %s/remote_endpoints.json" % out)
    return 0


def _parse_duration(s: str) -> int:
    s = s.strip().lower()
    if s.endswith("sec"):
        return int(s[:-3])
    if s.endswith("seconds"):
        return int(s[:-7])
    if s.endswith("s"):
        return int(s[:-1])
    if s.endswith("min"):
        return int(s[:-3]) * 60
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("h"):
        return int(s[:-1]) * 3600
    return int(s)


def cmd_contain(args: argparse.Namespace) -> int:
    """Load capture data, start sinkhole, apply firewall; block until SIGINT."""
    _require_root()
    if not nftables_available():
        print("error: nftables not available", file=sys.stderr)
        return 1
    out = Path(args.output_dir)
    endpoints_file = out / "remote_endpoints.json"
    if not endpoints_file.exists():
        print("error: run capture first (missing %s)" % endpoints_file, file=sys.stderr)
        return 1
    with open(endpoints_file) as f:
        data = json.load(f)
    endpoints = [(e["ip"], str(e["port"])) for e in data]
    if not endpoints:
        print("error: no remote endpoints in capture", file=sys.stderr)
        return 1

    allow_ips = list(args.allow_ip) if args.allow_ip else []
    use_dns_sinkhole = not args.no_dns_sinkhole

    pcap_path = out / "capture.pcap"
    replay_db = build_replay_db(pcap_path) if pcap_path.exists() else {}
    from .replay import save_replay_db
    if replay_db:
        save_replay_db(replay_db, out / "replay_db.json")
    sinkhole_cfg = SinkholeConfig(
        bind_host="127.0.0.1",
        local_port_start=args.port_start,
        stub_http_ok=True,
        stub_tcp_keepalive=True,
    )
    firewall_cfg = FirewallConfig(
        table_name="ir_sinkhole",
        drop_all_egress_after_redirect=not args.no_drop_egress,
    )
    server = create_sinkhole(
        endpoints,
        replay_db,
        sinkhole_cfg,
        port_start=args.port_start,
    )
    port_map = server.get_port_map()
    if not port_map:
        print("error: no sinkhole ports (no endpoints)", file=sys.stderr)
        return 1

    dns_port = DNS_SINKHOLE_PORT if use_dns_sinkhole else None

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    save_rules_to_file(
        port_map, firewall_cfg, out / "nft_containment.nft",
        allow_ips=allow_ips, dns_sinkhole_port=dns_port,
    )

    record_pcap_proc = None
    if getattr(args, "record_pcap", None):
        import subprocess
        rec_path = Path(args.record_pcap)
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        record_pcap_proc = subprocess.Popen(
            ["tshark", "-i", "lo", "-w", str(rec_path), "-f", "tcp or udp port 53"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        LOG.info("Recording containment traffic to %s (tshark PID %s)", rec_path, record_pcap_proc.pid)

    dns_transport = None

    def cleanup() -> None:
        nonlocal record_pcap_proc, dns_transport
        if dns_transport is not None:
            dns_transport.close()
            LOG.info("DNS sinkhole stopped")
        if record_pcap_proc is not None and record_pcap_proc.poll() is None:
            import subprocess as _sub
            record_pcap_proc.terminate()
            try:
                record_pcap_proc.wait(timeout=5)
            except _sub.TimeoutExpired:
                record_pcap_proc.kill()
        remove_firewall(firewall_cfg)
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)
        print("Containment stopped, firewall removed.")

    def sig_handler(*_):
        cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    async def run():
        nonlocal dns_transport
        host = sinkhole_cfg.bind_host

        if use_dns_sinkhole:
            dns_transport, _ = await start_dns_sinkhole(host, DNS_SINKHOLE_PORT)

        for i, (remote_ip, remote_port) in enumerate(endpoints):
            local_port = args.port_start + i
            key = (remote_ip, remote_port)
            chunks = replay_db.get(key, [])
            from .sinkhole import _make_handler
            handler = _make_handler(key, chunks, sinkhole_cfg)
            s = await asyncio.start_server(handler, host, local_port)
            server._servers.append(s)
            LOG.info("Sinkhole %s:%d -> %s:%s (%d chunks)", host, local_port, remote_ip, remote_port, len(chunks))

        apply_firewall(
            port_map, firewall_cfg,
            allow_ips=allow_ips,
            dns_sinkhole_port=dns_port,
        )

        if not args.no_conntrack_flush:
            flush_conntrack(port_map, allow_ips=allow_ips)

        features = []
        features.append("TCP sinkhole (%d endpoints)" % len(endpoints))
        if use_dns_sinkhole:
            features.append("DNS sinkhole (UDP 53)")
        if not args.no_conntrack_flush:
            features.append("conntrack flushed")
        if allow_ips:
            features.append("whitelist: %s" % ", ".join(allow_ips))
        if not args.no_drop_egress:
            features.append("egress blocked")

        print("Containment active [%s]. Ctrl+C to stop." % " | ".join(features))
        await asyncio.gather(*[s.serve_forever() for s in server._servers])

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    cleanup()
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    """Remove firewall and clear PID file (if process is not running)."""
    _require_root()
    firewall_cfg = FirewallConfig(table_name="ir_sinkhole")
    remove_firewall(firewall_cfg)
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)
            print("Containment process %s still running; send SIGTERM to stop." % pid, file=sys.stderr)
        except (ProcessLookupError, ValueError):
            PID_FILE.unlink(missing_ok=True)
            print("PID file removed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ir-sinkhole",
        description="Incident Response Sinkhole — containment without triggering malware disconnect behaviors",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # status
    sub.add_parser("status", help="Show current connections and containment state")

    # capture
    p_cap = sub.add_parser("capture", help="Capture connections and optional PCAP for replay")
    p_cap.add_argument("-d", "--duration", default="15m", help="Duration: 15m, 1h, 2h, or seconds")
    p_cap.add_argument("-o", "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Output directory")
    p_cap.add_argument("-i", "--interface", default="any", help="Interface for tshark")
    p_cap.add_argument("--poll-interval", type=int, default=5, help="Connection poll interval (s)")
    p_cap.add_argument("--no-tshark", dest="tshark", action="store_false", help="Disable tshark PCAP")
    p_cap.add_argument("--tshark-filter", default="tcp", help="tshark capture filter (BPF)")

    # contain
    p_contain = sub.add_parser("contain", help="Start sinkhole and redirect traffic (run after capture)")
    p_contain.add_argument("-o", "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Capture output directory")
    p_contain.add_argument("--port-start", type=int, default=19000, help="First local port for sinkhole")
    p_contain.add_argument("--no-drop-egress", action="store_true", help="Do not drop other egress (only redirect)")
    p_contain.add_argument("--record-pcap", type=Path, metavar="PATH", help="Run tshark during containment, write PCAP to PATH")
    p_contain.add_argument("--allow-ip", action="append", metavar="IP", help="Whitelist IP from containment (e.g. SSH jump host). Repeatable.")
    p_contain.add_argument("--no-dns-sinkhole", action="store_true", help="Disable DNS sinkhole (UDP 53 redirect)")
    p_contain.add_argument("--no-conntrack-flush", action="store_true", help="Do not flush established connections on start")

    # stop
    sub.add_parser("stop", help="Remove firewall rules and PID file")

    args = parser.parse_args()
    setup_logging("DEBUG" if args.verbose else "INFO")

    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "capture":
        return cmd_capture(args)
    if args.cmd == "contain":
        return cmd_contain(args)
    if args.cmd == "stop":
        return cmd_stop(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
