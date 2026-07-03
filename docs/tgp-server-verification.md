# TGP Server Verification

Use these checks before and after VPS deployment. They are designed to avoid
the user's real VPS during local smoke testing and to avoid local TUN, system
proxy, route, firewall, systemd, or Docker changes.

## Before VPS Deployment

Run the local smoke test from `tachyon-core`:

```bash
bash scripts/smoke-tgp-relay.sh
```

Equivalent direct command:

```bash
mise exec -- go test ./internal/app -run '^TestTGPRelaySmokeVerification$' -count=1 -v
```

The smoke test only binds temporary `127.0.0.1` UDP ports. It verifies:

- PSK-authenticated TGP handshake succeeds.
- Missing or wrong PSK handshakes are rejected.
- An allowed UDP target receives an echo-like relay round trip.
- Denied ports and unknown targets do not receive relay traffic.
- Empty `allowed_targets` remains deny-all, and wildcard relay targets are
  rejected.

It does not start the client pipeline, create TUN devices, or change host
networking.

## After VPS Deployment

On the VPS, run the read-only verifier that matches the deployment type:

```bash
sudo bash scripts/verify-server.sh
sudo bash scripts/verify-server.sh --mode docker
```

For a copied binary/config pair, or before starting a service:

```bash
bash scripts/verify-server.sh --mode config --binary ./tachyon-core --config ./server.json
```

`verify-server.sh` validates the binary and config, checks service/container
state when requested, summarizes `allowed_targets`, inspects the UDP listener,
and tails logs with PSK redaction. It intentionally does not change firewall
rules, cloud security groups, Docker, systemd, or packet filters.

## Output to Share

When asking for help, provide:

- The exact command you ran.
- The full `verify-server.sh` output after reviewing it.
- Whether the VPS cloud security group allows inbound UDP on `server.listen`.
- The Prism/Core versions involved, if testing from Prism.
- Any client-side error text with secrets removed.

Never share `tgp.auth.psk`. The verifier redacts common PSK forms, but review
the output before posting it publicly. You may redact public IPs, account IDs,
hostnames, or game target names if needed; keep the UDP port, deployment mode,
validation status, and `allowed_targets` shape visible enough to diagnose.
