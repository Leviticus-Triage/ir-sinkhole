"""
Build replay database from PCAP: extract server->client TCP payloads per (remote_ip, remote_port)
for use by the sinkhole when mimicking C2 responses.
"""
import logging
from collections import defaultdict
from pathlib import Path

LOG = logging.getLogger(__name__)

# Replay DB: (remote_ip, remote_port) -> list of byte chunks (server->client payloads in order)
ReplayDB = dict[tuple[str, str], list[bytes]]


def _read_pcap_with_scapy(pcap_path: Path) -> ReplayDB:
    """Use scapy to reassemble TCP streams and extract server->client payloads."""
    try:
        from scapy.all import rdpcap, TCP, IP
    except ImportError:
        LOG.warning("scapy not available, replay DB will be empty")
        return {}

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        return {}

    # Stream key: (our_ip, our_port, remote_ip, remote_port) - we consider "server" = remote (C2)
    # Server->client = remote -> our. We want payload where src=remote, dst=our.
    streams: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = defaultdict(list)

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as e:
        LOG.warning("rdpcap failed: %s", e)
        return {}

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            continue
        # Identify direction: from C2 (server) to us (client) => src is remote, dst is local
        src_ip = ip.src
        dst_ip = ip.dst
        sport = tcp.sport
        dport = tcp.dport
        seq = tcp.seq
        # Stream: (local_ip, local_port, remote_ip, remote_port) for "our" side as client
        # So client = (dst_ip, dport) when packet is from server (src_ip, sport) -> (dst_ip, dport)
        # So stream key client-side: (dst_ip, dport, src_ip, sport)
        stream_key = (dst_ip, dport, src_ip, sport)
        streams[stream_key].append((seq, payload))

    # Sort by seq per stream and concatenate (simplified: we don't do full reassembly, we append in order)
    replay: ReplayDB = defaultdict(list)
    for (local_ip, local_port, remote_ip, remote_port), chunks in streams.items():
        chunks_sorted = sorted(chunks, key=lambda x: x[0])
        payloads = [c for _, c in chunks_sorted]
        key = (remote_ip, str(remote_port))
        replay[key].extend(payloads)

    # Merge streams that share same (remote_ip, remote_port): concatenate all chunks
    merged: ReplayDB = {}
    for (remote_ip, remote_port), chunks in replay.items():
        merged[(remote_ip, remote_port)] = chunks
    return merged


def _read_pcap_with_dpkt(pcap_path: Path) -> ReplayDB:
    """Fallback: use dpkt if available for TCP stream extraction."""
    try:
        import dpkt
    except ImportError:
        return {}

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        return {}

    # dpkt: read pcap and group by (src, sport, dst, dport) for TCP
    streams: dict[tuple[str, int, str, int], list[bytes]] = defaultdict(list)
    try:
        with open(pcap_path, "rb") as f:
            pc = dpkt.pcap.Reader(f)
            for _ts, buf in pc:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp = ip.data
                    payload = bytes(tcp.data) if tcp.data else b""
                    if not payload:
                        continue
                    src_ip = dpkt.socket.inet_to_str(ip.src)
                    dst_ip = dpkt.socket.inet_to_str(ip.dst)
                    sport = tcp.sport
                    dport = tcp.dport
                    stream_key = (dst_ip, dport, src_ip, sport)
                    streams[stream_key].append(payload)
                except Exception:
                    continue
    except Exception as e:
        LOG.warning("dpkt pcap read failed: %s", e)
        return {}

    merged: ReplayDB = {}
    for (local_ip, local_port, remote_ip, remote_port), chunks in streams.items():
        key = (remote_ip, str(remote_port))
        merged[key] = chunks
    return merged


def build_replay_db(pcap_path: Path) -> ReplayDB:
    """
    Build replay database from pcap. Returns dict (remote_ip, remote_port) -> list of bytes.
    Uses scapy first, then dpkt fallback.
    """
    db = _read_pcap_with_scapy(pcap_path)
    if not db and pcap_path.exists():
        db = _read_pcap_with_dpkt(pcap_path)
    LOG.info("Replay DB: %d endpoint(s)", len(db))
    return db


def save_replay_db(db: ReplayDB, path: Path) -> None:
    """Persist replay DB as JSON (base64 payloads)."""
    import base64
    out = {}
    for (ip, port), chunks in db.items():
        key = f"{ip}:{port}"
        out[key] = [base64.b64encode(c).decode("ascii") for c in chunks]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        import json
        json.dump(out, f, indent=2)


def load_replay_db(path: Path) -> ReplayDB:
    """Load replay DB from JSON."""
    import base64
    import json
    db: ReplayDB = {}
    if not path.exists():
        return db
    with open(path) as f:
        raw = json.load(f)
    for key, chunks_b64 in raw.items():
        if ":" in key:
            ip, port = key.rsplit(":", 1)
            db[(ip, port)] = [base64.b64decode(c) for c in chunks_b64]
    return db
