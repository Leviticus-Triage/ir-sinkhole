# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/Leviticus-Triage/ir-sinkhole/releases/tag/v1.0.0
