"""
nftables rules: DNAT outbound connections to C2 endpoints to local sinkhole ports,
and optionally drop all other egress (containment).
"""
import logging
import subprocess
from pathlib import Path
from typing import Optional

from .config import FirewallConfig

LOG = logging.getLogger(__name__)

# (remote_ip, remote_port) -> local_port
PortMap = dict[tuple[str, str], int]


def _nft(cmd: str, check_only: bool = False) -> tuple[int, str]:
    """Run an nft command. Returns (returncode, stderr).
    If check_only=True, uses -c to validate without applying."""
    full = ["nft"] + (["-c"] if check_only else []) + [cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=10)
        return r.returncode, (r.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, str(e)


def nftables_available() -> bool:
    code, _ = _nft("list tables", check_only=True)
    return code == 0


def apply_firewall(port_map: PortMap, config: FirewallConfig, family: str = "ip") -> bool:
    """
    Add table and chain; add DNAT rules for each (remote_ip, remote_port) -> 127.0.0.1:local_port;
    then drop all other egress if config.drop_all_egress_after_redirect.
    """
    table = config.table_name
    chain = config.chain_name

    _nft(f"delete table {family} {table}")

    code, err = _nft(f"add table {family} {table}")
    if code != 0:
        LOG.error("Failed to create nftables table %s: %s", table, err)
        return False
    LOG.info("Created nftables table %s %s", family, table)

    code, err = _nft(f"add chain {family} {table} {chain} {{ type nat hook output priority -100 ; policy accept ; }}")
    if code != 0:
        LOG.error("Failed to create chain %s (type nat, hook output): %s", chain, err)
        return False
    LOG.info("Created chain %s (type nat, hook output, priority -100)", chain)

    _nft(f"add rule {family} {table} {chain} oifname \"lo\" accept")

    ok_count = 0
    fail_count = 0
    for (remote_ip, remote_port), local_port in port_map.items():
        cmd = f"add rule {family} {table} {chain} ip daddr {remote_ip} tcp dport {remote_port} dnat to 127.0.0.1:{local_port}"
        code, err = _nft(cmd)
        if code != 0:
            LOG.warning("DNAT rule failed for %s:%s: %s", remote_ip, remote_port, err.strip())
            fail_count += 1
            continue
        ok_count += 1

    LOG.info("DNAT rules applied: %d OK, %d failed (out of %d endpoints)", ok_count, fail_count, len(port_map))

    if config.drop_all_egress_after_redirect:
        code, err = _nft(f"add rule {family} {table} {chain} drop")
        if code != 0:
            LOG.warning("Egress drop rule failed: %s", err.strip())
        else:
            LOG.info("Egress drop rule added — all non-redirected outbound traffic blocked")
    return True


def remove_firewall(config: FirewallConfig, family: str = "ip") -> bool:
    """Remove our table (and all chains/rules)."""
    table = config.table_name
    code, err = _nft(f"delete table {family} {table}")
    if code != 0:
        LOG.warning("nft delete table failed: %s", err)
        return False
    LOG.info("Firewall table %s removed", table)
    return True


def save_rules_to_file(port_map: PortMap, config: FirewallConfig, path: Path, family: str = "ip") -> None:
    """Write nftables script to path for manual inspection or restore."""
    table = config.table_name
    chain = config.chain_name
    lines = [
        f"#!/usr/sbin/nft -f",
        f"flush table {family} {table} 2>/dev/null",
        f"delete table {family} {table} 2>/dev/null",
        f"add table {family} {table}",
        f"add chain {family} {table} {chain} {{ type nat hook output priority -100 ; policy accept ; }}",
        "add rule %s %s %s oifname \"lo\" accept" % (family, table, chain),
    ]
    for (remote_ip, remote_port), local_port in port_map.items():
        lines.append(f"add rule {family} {table} {chain} ip daddr {remote_ip} tcp dport {remote_port} dnat to 127.0.0.1:{local_port}")
    if config.drop_all_egress_after_redirect:
        lines.append(f"add rule {family} {table} {chain} drop")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    LOG.info("Rules written to %s", path)
