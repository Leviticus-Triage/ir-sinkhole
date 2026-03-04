# Security Policy

## Supported versions

We provide security-related updates for the latest release branch. Older versions are not actively supported.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

If you believe you have found a security-relevant issue in IR Sinkhole (e.g. privilege escalation, unintended network exposure, or integrity bypass), we ask that you report it in a way that allows us to address it before public disclosure.

**Please do not open a public GitHub issue for security vulnerabilities.**

- **Preferred:** Send a private report to the maintainers (e.g. via GitHub Security Advisories: *Security* → *Advisories* → *Report a vulnerability* for this repository, if enabled).
- **Alternative:** If you have no other channel, send an email to the address listed in the repository or in the project metadata, with a clear subject (e.g. “IR Sinkhole – security report”) and a description of the issue, steps to reproduce, and impact.

We will acknowledge receipt and aim to respond within a reasonable time. We may ask for clarification or more details. Once the issue is understood and (if applicable) a fix is prepared, we will coordinate with you on disclosure timing and credit.

**Thank you for helping keep IR Sinkhole safe for use in incident response environments.**

## Security-related design notes

- The tool requires **root** for capture and containment (nftables, optional tshark). It is intended to be run only on hosts under controlled incident response.
- IR Sinkhole does **not** transmit any data to third parties; all state remains on the host in the configured output directory.
- When deploying from source or install scripts, verify the origin and integrity of the code (e.g. checksums, tags, or signed releases) according to your organization’s policies.
