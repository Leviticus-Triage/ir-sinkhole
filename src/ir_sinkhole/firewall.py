"""
nftables rules: DNAT outbound connections to C2 endpoints to local sinkhole ports,
DNS redirect to local sinkhole, conntrack flush, and optional egress drop.
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


def apply_firewall(
    port_map: PortMap,
    config: FirewallConfig,
    family: str = "ip",
    allow_ips: Optional[list[str]] = None,
    dns_sinkhole_port: Optional[int] = None,
) -> bool:
    """
    Build the full containment firewall:
    1. Create table + nat output chain
    2. Allow loopback
    3. Whitelist management IPs (--allow-ip)
    4. DNS redirect to local sinkhole (UDP 53)
    5. DNAT rules per captured endpoint
    6. Optional: drop all remaining egress
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

    if allow_ips:
        for ip in allow_ips:
            _nft(f"add rule {family} {table} {chain} ip daddr {ip} accept")
            LOG.info("Whitelisted management IP: %s", ip)

    if dns_sinkhole_port:
        code, err = _nft(
            f"add rule {family} {table} {chain} udp dport 53 dnat to 127.0.0.1:{dns_sinkhole_port}"
        )
        if code != 0:
            LOG.warning("DNS redirect rule failed: %s", err.strip())
        else:
            LOG.info("DNS redirect: UDP 53 → 127.0.0.1:%d", dns_sinkhole_port)

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
            LOG.info("Egress drop rule added - all non-redirected outbound traffic blocked")
    return True


def flush_conntrack(
    port_map: PortMap,
    allow_ips: Optional[list[str]] = None,
) -> int:
    """Flush conntrack entries for captured endpoints so established connections
    are forced to re-establish through the DNAT rules.
    Returns number of flushed entries."""
    flushed = 0
    allow_set = set(allow_ips) if allow_ips else set()
    for (remote_ip, remote_port), _ in port_map.items():
        if remote_ip in allow_set:
            continue
        try:
            r = subprocess.run(
                ["conntrack", "-D", "-d", remote_ip, "-p", "tcp", "--dport", str(remote_port)],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                count = 1
                for line in r.stdout.strip().split("\n"):
                    if "flow" in line.lower():
                        try:
                            count = int(line.split()[0])
                        except (ValueError, IndexError):
                            pass
                flushed += count
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    if flushed > 0:
        LOG.info("Conntrack flush: %d established connection(s) killed → will reconnect through DNAT", flushed)
    else:
        LOG.info("Conntrack flush: no established entries found for captured endpoints")
    return flushed


def remove_firewall(config: FirewallConfig, family: str = "ip") -> bool:
    """Remove our table (and all chains/rules)."""
    table = config.table_name
    code, err = _nft(f"delete table {family} {table}")
    if code != 0:
        LOG.warning("nft delete table failed: %s", err)
        return False
    LOG.info("Firewall table %s removed", table)
    return True


def save_rules_to_file(
    port_map: PortMap,
    config: FirewallConfig,
    path: Path,
    family: str = "ip",
    allow_ips: Optional[list[str]] = None,
    dns_sinkhole_port: Optional[int] = None,
) -> None:
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
    if allow_ips:
        for ip in allow_ips:
            lines.append(f"add rule {family} {table} {chain} ip daddr {ip} accept")
    if dns_sinkhole_port:
        lines.append(f"add rule {family} {table} {chain} udp dport 53 dnat to 127.0.0.1:{dns_sinkhole_port}")
    for (remote_ip, remote_port), local_port in port_map.items():
        lines.append(f"add rule {family} {table} {chain} ip daddr {remote_ip} tcp dport {remote_port} dnat to 127.0.0.1:{local_port}")
    if config.drop_all_egress_after_redirect:
        lines.append(f"add rule {family} {table} {chain} drop")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    LOG.info("Rules written to %s", path)
