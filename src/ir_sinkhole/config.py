"""
Configuration schema and defaults for IR Sinkhole.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CaptureConfig:
    """Capture phase settings."""
    duration_seconds: int = 900  # 15 min default
    interface: str = "any"
    output_dir: Path = field(default_factory=lambda: Path("/var/lib/ir-sinkhole"))
    poll_interval_seconds: int = 5
    run_tshark: bool = True
    tshark_capture_filter: str = "tcp"  # optional BPF


@dataclass
class SinkholeConfig:
    """Sinkhole listener settings."""
    bind_host: str = "127.0.0.1"
    local_port_start: int = 19000  # first port for DNAT target
    stub_http_ok: bool = True  # send HTTP 200 for unknown protocols
    stub_tcp_keepalive: bool = True  # else just keep socket open
    replay_chunk_delay_ms: float = 0.0  # optional delay between replay chunks


@dataclass
class FirewallConfig:
    """Firewall (nftables) settings."""
    table_name: str = "ir_sinkhole"
    chain_name: str = "output"
    drop_all_egress_after_redirect: bool = True  # block real internet


@dataclass
class Config:
    """Full application config."""
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    sinkhole: SinkholeConfig = field(default_factory=SinkholeConfig)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    require_root: bool = True  # capture, firewall need root
    log_level: str = "INFO"
