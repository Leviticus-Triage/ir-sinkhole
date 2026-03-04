# Contributing to IR Sinkhole

Thank you for your interest in contributing. The following guidelines help keep the project consistent and reviewable.

## Code of conduct

- Be respectful and professional. This project is used in incident response and security contexts; clarity and reliability matter.
- Focus on technical merit; avoid off-topic or personal remarks.

## How to contribute

- **Bug reports and feature ideas:** Open a GitHub issue. For bugs, include steps to reproduce, environment (OS, Python version), and (if applicable) relevant log or PCAP excerpts (sanitized).
- **Code or documentation:** Open a pull request (PR) against the default branch. Link any related issues.

## Development setup

```bash
git clone https://github.com/Leviticus-Triage/ir-sinkhole.git
cd ir-sinkhole
python3 -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
```

- **Tests:** Run with `pytest` from the project root. New behavior should be covered by tests where practical.
- **Style:** Keep the existing style (e.g. Black-style formatting if adopted). Prefer clear names and short functions.
- **Root-only behavior:** Capture and containment require root and nftables; tests that need these can be skipped or run in CI with appropriate privileges.

## Scope of the project

- **In scope:** Improving capture (ss/conntrack/tshark), replay (PCAP parsing, stub behavior), sinkhole servers, nftables rules, CLI, documentation, and tests.
- **Out of scope (unless explicitly agreed):** Adding telemetry, optional “phone home” features, or changes that weaken containment or evidence preservation.

## Pull request process

1. Branch from the default branch, make changes, and add or update tests as needed.
2. Ensure `pytest` passes.
3. Update README or docs if you change behavior or add options.
4. In the PR description, briefly explain the change and why it’s useful.
5. Maintainers will review and may request changes. Once approved, your PR can be merged.

## Documentation

- User-facing behavior belongs in the main **README.md**.
- Design, threat model, and technical details belong in **docs/ARCHITECTURE.md**.
- Security reporting is described in **SECURITY.md**.

Thank you for contributing to IR Sinkhole.
