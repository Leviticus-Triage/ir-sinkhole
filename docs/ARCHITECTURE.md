# IR Sinkhole — Architecture and Design

This document describes the design rationale, threat model, data flow, and technical decisions for IR Sinkhole. It is intended for CSIRT/CERT reviewers, security architects, and contributors.

---

## 1. Problem statement

During incident response, analysts often need to **contain** a compromised host (stop further damage and exfiltration) while **preserving evidence** (memory, disk, logs). If the host is simply disconnected from the network, many malware families detect the loss of connectivity and trigger:

- **Dead-man switch / persistence degradation:** cleanup routines, process exit, or removal of artifacts
- **Anti-forensics:** log wiping, file encryption or deletion, overwriting of sensitive data
- **Evasive behavior:** process hollowing, injection, or config rotation to hinder analysis

So the goal is: **containment without signaling “disconnect”** to the malware. The host must appear to remain connected to the same remote endpoints (e.g. C2), while in reality no traffic leaves the host.

---

## 2. Threat model and assumptions

- **Adversary:** Malware (RAT, infostealer, etc.) that maintains outbound TCP connections to C2 or other remote services and may react to connection failure or timeout.
- **Defender:** Incident responder with root on the affected host, who can run capture and containment tools and modify local firewall (nftables).
- **Trust:** The tool itself is run in a controlled IR context; we do not model supply-chain compromise of the tool. Output directories and PCAPs are treated as sensitive and should be handled according to organizational IR procedures.
- **Scope:** Single host. No assumption of network-level sinkholing (e.g. at perimeter); everything is host-local.

---

## 3. High-level design

1. **Capture phase (pre-isolation)**  
   - Poll active TCP connections (`ss`, or `conntrack` as fallback) at a configurable interval.  
   - Optionally run `tshark` to record a PCAP of the same period.  
   - Persist: list of unique remote endpoints `(IP, port)` and, from PCAP, server→client TCP payloads per endpoint for replay.

2. **Containment phase**  
   - For each captured endpoint, start a **local TCP server** on `127.0.0.1` on a dedicated port (e.g. 19000, 19001, …).  
   - Install **nftables** rules in the `output` hook: for outbound packets whose destination is one of the captured endpoints, **DNAT** to the corresponding local sinkhole port. Optionally **drop** all other egress.  
   - When the malware (or any process) tries to connect to the original remote IP:port, the kernel redirects the connection to the local server. The sinkhole either **replays** server→client payloads from the PCAP or sends a minimal **HTTP 200** stub and keeps the connection open.  
   - Result: the application sees a successful connection and receives data (replay or stub); no packet leaves the host to the real C2.

3. **Forensics phase**  
   - Analyst can run memory/disk capture and live analysis while containment is active. Optionally, `--record-pcap` runs tshark on loopback to record the sinkhole traffic for anomaly analysis.

---

## 4. Data flow

```
[ Malware / App ]  -->  connect(remote_ip, remote_port)
        |
        v
[ Kernel / nftables output hook ]
        |  DNAT: (remote_ip, remote_port) --> (127.0.0.1, sinkhole_port)
        v
[ Sinkhole TCP server on 127.0.0.1:sinkhole_port ]
        |  Replay from PCAP or HTTP stub
        v
[ Malware / App ]  sees response, no disconnect
```

Capture phase:

```
[ Host traffic ] --> tshark --> capture.pcap
[ ss / conntrack ] --> connections.jsonl --> remote_endpoints.json
[ capture.pcap ] --> scapy/dpkt --> replay_db (server→client payloads per endpoint)
```

---

## 5. Technical choices

- **nftables (not iptables):** Modern, scriptable, and easier to manage a dynamic set of DNAT rules. One table per run; cleanup is a single table delete.
- **Per-endpoint local port:** Each (remote_ip, remote_port) is mapped to a distinct local port so the sinkhole can look up replay data by the port on which the connection arrived.
- **Replay vs. stub:** If we have PCAP-derived payloads for that endpoint, we replay them in order to mimic C2 behavior. Otherwise we send a minimal HTTP 200 and keep the socket open to avoid RST/timeout.
- **TCP only:** UDP or other protocols would require different handling (e.g. stateless reply or stateful proxy). Current scope is TCP-only for simplicity and coverage of most C2-over-HTTP(s)/custom-TCP scenarios.
- **IPv4 only (current):** Rules are in the `ip` family. IPv6 can be added with a separate `ip6` table and the same logic.

---

## 6. Limitations (reference)

- TCP only; no UDP/ICMP.
- Outbound-only redirection; no modification of inbound traffic.
- IPv4 only in the reference nftables rules.
- Replay is best-effort (sequence-ordered TCP payloads; no full reassembly of overlapping/retransmitted segments).
- No TLS decryption; replay is at TCP payload level (opaque bytes).
- Single-host tool; no distributed or coordinated sinkhole.

See also [Scope and limitations](../README.md#scope-and-limitations) in the main README.

---

## 7. Possible future extensions

- **IPv6:** Add `ip6` nftables table and matching sinkhole port mapping.
- **Structured logging:** JSON logs (e.g. per redirected connection) for SIEM integration.
- **UDP:** Optional stateless or stateful handling for UDP C2 (DNS, custom).
- **Config file:** YAML/JSON config for automation and repeatable deployments.

These are not committed roadmap items; they are listed to show where the design could grow without changing the core model.

---

## 8. References and further reading

- NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide) — containment and evidence preservation.
- SANS Institute — Incident Response Process and containment strategies.
- MITRE ATT&CK — Defense Evasion, Impact (e.g. Data Encrypted for Impact, Inhibit System Recovery) for behaviors that may be triggered on disconnect.

---

*Last updated for IR Sinkhole 1.0.0.*
