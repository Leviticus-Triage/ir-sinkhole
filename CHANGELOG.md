# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-04

### Added

- **DNS Sinkhole:** Local asyncio UDP server intercepts all DNS queries (nftables UDP 53 redirect → `dns_sinkhole.py`). Responds with `127.0.0.1` / `::1`. Logs every query. Mitigates DNS tunneling C2 (T1071.004).
- **Conntrack flush:** `flush_conntrack()` purges existing NAT entries for captured endpoints on containment start, forcing reconnections through DNAT rules. Prevents established connections from bypassing containment.
- **Management IP whitelist:** `--allow-ip` flag exempts specified IPs from all containment rules (DNAT, egress drop, DNS redirect). Prevents responder lockout during remote IR.
- **Companion triage script:** `scripts/examples/check-infection-orderbuddy.sh` - 17-check read-only host triage (cross-platform macOS + Linux). Originally developed for a real Operation Dream Job / OrderBuddy incident.
- **Containment coverage matrix:** Honest gap analysis in README and ARCHITECTURE.md documenting what is covered, what remains outside scope, and which complementary tools fill the gaps.
- **IR toolkit integration diagram:** Mermaid flowchart showing how IR Sinkhole fits into a broader incident response toolchain.

### Changed

- `firewall.py`: Removed `-c` dry-run flag from `_nft()` - rules are now actually applied. Changed chain type from `filter` to `nat` (priority -100) for DNAT support.
- `main.py`: Duration parser now accepts `s`, `sec`, `seconds`, `min` suffixes.
- `ir-sinkhole-menu.sh`: Fixed ANSI-C quoting for colors, banner frame alignment, interactive prompts for DNS sinkhole / conntrack / whitelist.

### Fixed

- nftables rules were validated but never executed (dry-run bug).
- Wrong chain type (`filter` instead of `nat`) prevented DNAT from working.
- Color escape sequences printed literally in menu script.
- Menu exited immediately when run via `curl | bash` (stdin issue).

---

## [1.0.0] - 2026-02-28

### Added

- **Capture:** Poll active TCP connections via `ss` and `conntrack`, optional tshark PCAP capture. Output: `connections.jsonl`, `remote_endpoints.json`, `capture.pcap`.
- **Replay DB:** Build server→client payload map from PCAP (scapy with dpkt fallback). Save/load as JSON for inspection.
- **Sinkhole:** Per-endpoint asyncio TCP servers on configurable local ports. Replay from PCAP or send HTTP 200 stub and keep connection open.
- **Firewall:** nftables DNAT rules to redirect outbound traffic to captured endpoints to local sinkhole ports; optional drop of all other egress.
- **CLI:** `status`, `capture`, `contain`, `stop` with configurable duration, output dir, interface, port range, and `--record-pcap` for containment-phase PCAP.
- **Documentation:** README (usage, workflow, scope, security), ARCHITECTURE.md (design, threat model), SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, CITATION.cff.
- **Tests:** Pytest tests for capture parsing and replay DB save/load.
- **Install:** `install.sh` for one-liner deploy; pyproject.toml and `ir-sinkhole` entry point.

### Limitations (documented)

- TCP and IPv4 only; outbound-only redirection; single-host; best-effort replay without full TCP reassembly.

[1.1.0]: https://github.com/Leviticus-Triage/ir-sinkhole/releases/tag/v1.1.0
[1.0.0]: https://github.com/Leviticus-Triage/ir-sinkhole/releases/tag/v1.0.0
