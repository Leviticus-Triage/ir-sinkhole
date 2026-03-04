# Technical reference

Code structure, module responsibilities, and CLI options for IR Sinkhole.

---

## 1. Repository layout

```
ir-sinkhole/
├── src/ir_sinkhole/          # Python package
│   ├── __init__.py           # Version
│   ├── config.py             # CaptureConfig, SinkholeConfig, FirewallConfig
│   ├── capture.py            # Connection polling, tshark, endpoints
│   ├── replay.py             # PCAP → replay DB (scapy/dpkt), save/load JSON
│   ├── sinkhole.py           # Asyncio TCP servers, replay/stub handler
│   ├── dns_sinkhole.py       # DNS interception (UDP 53, asyncio)
│   ├── firewall.py           # nftables add/remove, conntrack flush, script export
│   └── main.py               # CLI: status, capture, contain, stop
├── scripts/
│   ├── run.sh                # Bootstrap for curl one-liner
│   ├── ir-sinkhole-menu.sh   # ASCII menu + install (curl one-liner)
│   └── examples/
│       └── check-infection-orderbuddy.sh  # 17-check IR triage script
├── docs/
│   ├── ARCHITECTURE.md       # Design, threat model, data flow
│   ├── HOWTO.md              # Workflows, test scenario
│   ├── TECHNICAL.md          # This file
│   └── systemd-example.md    # Optional systemd unit
├── tests/
│   ├── test_capture.py       # ss parsing, unique endpoints
│   └── test_replay.py        # Replay DB save/load, empty pcap
├── pyproject.toml            # Build, deps, entry point ir-sinkhole
├── install.sh                # Non-interactive install (clone, venv, link)
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
└── CHANGELOG.md
```

---

## 2. Module overview

### 2.1 `config.py`

- **CaptureConfig:** `duration_seconds`, `interface`, `output_dir`, `poll_interval_seconds`, `run_tshark`, `tshark_capture_filter`
- **SinkholeConfig:** `bind_host`, `local_port_start`, `stub_http_ok`, `stub_tcp_keepalive`, `replay_chunk_delay_ms`
- **FirewallConfig:** `table_name`, `chain_name`, `drop_all_egress_after_redirect`

### 2.2 `capture.py`

| Function / class | Purpose |
|------------------|--------|
| `get_active_tcp_connections()` | Run `ss -tnap` or `conntrack -L`, return list of dicts (local_ip, local_port, remote_ip, remote_port, state, pid). |
| `unique_remote_endpoints(connections)` | Deduplicate to list of `(remote_ip, remote_port)`. |
| `TsharkCapture(interface, pcap_path, capture_filter)` | Start/stop tshark subprocess writing to `pcap_path`. |
| `run_capture(config, stop_event=None)` | Loop for `duration_seconds`, poll connections, append to `connections.jsonl`, run tshark if enabled; write `remote_endpoints.json` at end. |

### 2.3 `replay.py`

| Function | Purpose |
|----------|--------|
| `build_replay_db(pcap_path)` | Parse PCAP (scapy, else dpkt), group server→client TCP payloads by `(remote_ip, remote_port)`; return `ReplayDB` dict. |
| `save_replay_db(db, path)` | Serialize to JSON (base64 payloads). |
| `load_replay_db(path)` | Deserialize from JSON. |

`ReplayDB` type: `dict[(str, str), list[bytes]]` — key is `(remote_ip, remote_port)`.

### 2.4 `sinkhole.py`

| Function / class | Purpose |
|------------------|--------|
| `_handle_client(reader, writer, remote_key, replay_chunks, config)` | Async: send `replay_chunks` or HTTP 200 stub; optionally keep socket open (stub_tcp_keepalive). |
| `_make_handler(remote_key, replay_chunks, config)` | Returns a callback for `asyncio.start_server`. |
| `SinkholeServer(endpoints, replay_db, config, port_start)` | Holds `_port_map`: `(remote_ip, remote_port)` → local port. `get_port_map()` for firewall. |
| `create_sinkhole(...)` | Factory for `SinkholeServer`. |

Listening is done in `main.py` (contain): one `asyncio.start_server` per endpoint, then `apply_firewall(port_map)`, then `asyncio.gather(serve_forever...)`.

### 2.5 `dns_sinkhole.py`

| Function / class | Purpose |
|------------------|--------|
| `DNS_SINKHOLE_PORT` | Default bind port (15353); nftables redirects UDP 53 → this port. |
| `_build_response(data)` | Hand-parses DNS wire format (no external deps). Returns A=`127.0.0.1` or AAAA=`::1` response. |
| `DnsSinkholeProtocol` | `asyncio.DatagramProtocol` that logs all queries and responds locally. |
| `start_dns_sinkhole(bind_host, port)` | Creates the UDP transport; returns `(transport, queries_log)`. |

### 2.6 `firewall.py`

| Function | Purpose |
|----------|--------|
| `nftables_available()` | Run `nft list tables`, return true if exit 0. |
| `apply_firewall(port_map, config, family, allow_ips, dns_sinkhole_port)` | Create table `ir_sinkhole`, chain `output` (type nat, priority -100); whitelist `allow_ips`; per-endpoint DNAT; DNS redirect to `dns_sinkhole_port`; optional egress drop. |
| `remove_firewall(config, family="ip")` | `nft delete table ip ir_sinkhole`. |
| `save_rules_to_file(port_map, config, path, family, allow_ips, dns_sinkhole_port)` | Write an nft script to `path` for inspection or manual restore. |
| `flush_conntrack(port_map, allow_ips)` | Run `conntrack -D` for each captured endpoint (excluding whitelisted IPs) to force reconnections through DNAT. |

### 2.7 `main.py`

- **Entry point:** `ir_sinkhole.main:main` (set in `pyproject.toml`).
- **Subcommands:** `status`, `capture`, `contain`, `stop`.
- **contain:** Load `remote_endpoints.json`, build replay DB from `capture.pcap`, create sinkhole servers, optionally start DNS sinkhole, write PID and `nft_containment.nft`, register SIGINT/SIGTERM cleanup; apply firewall with whitelist and DNS redirect, flush conntrack, then `asyncio.gather(serve_forever...)`.
- **New flags:** `--allow-ip` (repeatable), `--no-dns-sinkhole`, `--no-conntrack-flush`.

---

## 3. CLI reference

| Command | Options | Defaults |
|---------|---------|----------|
| `ir-sinkhole status` | — | — |
| `ir-sinkhole capture` | `-d`, `-o`, `-i`, `--poll-interval`, `--no-tshark`, `--tshark-filter` | `15m`, `/var/lib/ir-sinkhole`, `any`, `5`, tshark on, `tcp` |
| `ir-sinkhole contain` | `-o`, `--port-start`, `--no-drop-egress`, `--record-pcap`, `--allow-ip`, `--no-dns-sinkhole`, `--no-conntrack-flush` | `/var/lib/ir-sinkhole`, `19000`, drop on, no record, DNS sinkhole on, conntrack flush on |
| `ir-sinkhole stop` | — | — |

Global: `-v` / `--verbose` for DEBUG logging.

---

## 4. Data files

| File | Format | Produced by | Consumed by |
|------|--------|-------------|-------------|
| `connections.jsonl` | One JSON object per line: `{ "elapsed_seconds", "count", "connections": [...] }` | capture | — (audit) |
| `remote_endpoints.json` | JSON array of `{ "ip", "port" }` | capture | contain |
| `capture.pcap` | PCAP | tshark in capture | replay (build_replay_db) |
| `replay_db.json` | JSON: `{ "ip:port": [ "base64...", ... ] }` | contain (from pcap) | — (optional; contain builds in memory) |
| `nft_containment.nft` | nft script | contain | — (inspection/restore) |

---

## 5. Dependencies

- **Python:** 3.10+
- **scapy:** PCAP parsing and replay DB (optional but recommended).
- **async-timeout:** Used by asyncio (dependency).
- **System:** nftables, tshark (optional), ss or conntrack.

See `pyproject.toml` for exact versions.
