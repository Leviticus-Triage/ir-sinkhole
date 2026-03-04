# Optional: Run containment as a systemd service

For environments where you want containment to run as a service (e.g. start after capture, survive terminal disconnect), you can use a oneshot or long-running service. **Use with care:** the service runs as root and modifies nftables.

## Prerequisites

- Capture has already been run; `remote_endpoints.json` (and optionally `capture.pcap`) exist in the output directory.
- `ir-sinkhole` is installed (e.g. under `/opt/ir-sinkhole` or via `/usr/local/bin/ir-sinkhole`).

## Example unit (long-running)

Create `/etc/systemd/system/ir-sinkhole-contain.service`:

```ini
[Unit]
Description=IR Sinkhole containment (redirect C2 traffic to local sinkhole)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ir-sinkhole contain -o /var/lib/ir-sinkhole
Restart=no
TimeoutStopSec=30
KillMode=control-group

# Security hardening (optional)
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ir-sinkhole /var/run
InaccessibleDirectories=/home /root

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl start ir-sinkhole-contain.service
# Check status
sudo systemctl status ir-sinkhole-contain.service
# Stop and remove firewall
sudo systemctl stop ir-sinkhole-contain.service
# Or: sudo ir-sinkhole stop
```

**Note:** `ProtectSystem=strict` and `ReadWritePaths` may need adjustment if your install or output paths differ. Ensure the unit can read `/var/lib/ir-sinkhole` and write PID/nft state as needed.

## Stopping containment

- `systemctl stop ir-sinkhole-contain.service` stops the process; the provided `ExecStart` (ir-sinkhole contain) handles nftables cleanup on exit.
- If the process is killed abruptly, run `sudo ir-sinkhole stop` to remove the firewall table and PID file.

This example is **optional** and not part of the default install. Adapt to your deployment and security policies.
