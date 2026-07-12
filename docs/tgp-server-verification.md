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
mise exec -- go test ./internal/app -run '^TestTGPRelay(SmokeVerification|ConfigDrivenSmoke)$' -count=1 -v
```

Validate the optional public verifier without contacting DNS or opening a
public socket:

```bash
bash -n scripts/verify-tgp-e2e.sh
bash scripts/verify-tgp-e2e.sh --self-test
env -u TACHYON_E2E_SERVER -u TACHYON_E2E_TARGET -u TACHYON_E2E_PSK \
  mise exec -- go test ./internal/app \
  -run '^(TestTGPRelayPublicE2EFromEnv|TestPublicE2EConfigFromEnv|TestResolvePublicE2EAddrLiteral)$' \
  -count=1 -v
```

With the three required environment variables unset, the public test skips
before DNS resolution or socket creation. Its local tests cover partial opt-in,
PSK length, payload size, response matcher conflicts, host/port parsing, and the
30-second timeout ceiling.

The smoke test only binds temporary `127.0.0.1` UDP ports. It verifies:

- PSK-authenticated TGP handshake succeeds.
- Missing or wrong PSK handshakes are rejected.
- Config-driven client/server settings can be wired into a working TGP relay
  path.
- An allowed UDP target receives an echo-like relay round trip.
- Denied ports and unknown targets do not receive relay traffic.
- Empty `allowed_targets` remains deny-all, and wildcard relay targets are
  rejected.

It does not start the TUN packet pipeline, create TUN devices, invoke Prism or
Xray, contact a real game server, or change host networking.
The local smoke test cannot replace verification on the real VPS, cloud
security group UDP exposure, carrier UDP reachability, or real game UDP
end-to-end validation.

## After VPS Deployment

Install with explicit relay targets. The installer accepts repeated
`--allow-target` entries:

```bash
sudo bash scripts/install-server.sh --version v0.1.0-alpha.17 --port 443 \
  --allow-target 'cidr=198.51.100.10/32,ports=27015'

sudo bash scripts/install-server-docker.sh --version v0.1.0-alpha.17 --port 443 \
  --allow-target 'domain=echo.example.com,ports=27015'
```

Use the narrowest UDP destination and port list you can. For public E2E
validation, prefer a UDP echo service you control and include that echo target
in `server.relay.allowed_targets`. Do not point the verifier at a real game
server unless you intentionally know how that server responds to arbitrary UDP
probes.

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

## Public TGP E2E

After `verify-server.sh` shows a valid binary/config, a running service or
container, a UDP listener, and non-empty `allowed_targets`, run the optional
client-side public E2E verifier from a machine that can reach the VPS:

```bash
printf '%s\n' '<copy-redacted-psk-here-locally>' > ./tgp.psk
bash scripts/verify-tgp-e2e.sh --mode public \
  --server vps.example.com:443 \
  --target echo.example.com:27015 \
  --psk-file ./tgp.psk
```

The target must be a controlled UDP echo endpoint that is explicitly allowed by
the VPS config. If the echo response is not exactly the request payload or
`echo:<payload>`, add one of:

```bash
--expect 'known-response'
--expect-prefix 'echo:'
```

Use only one response matcher. VPS and target DNS resolution, the TGP
handshake, and the response wait share the configured timeout (maximum 30
seconds). The response must also identify the resolved target address and port.

`verify-tgp-e2e.sh` does not create TUN devices, alter routes, enable system
proxy, or change firewall/systemd/Docker state. Its default mode is still local
loopback smoke; public UDP is contacted only when `--server`, `--target`, and a
PSK are provided.

Layer the checks this way:

- Local loopback smoke: `scripts/smoke-tgp-relay.sh`; proves Core TGP relay
  logic and config-driven runtime wiring without host networking changes.
- VPS verification: `scripts/verify-server.sh`; proves the installed server
  binary/config/listener/service shape and summarizes `allowed_targets`.
- Public TGP E2E: `scripts/verify-tgp-e2e.sh --mode public`; proves a client
  can complete a TGP handshake to the VPS and relay one UDP echo payload to an
  explicitly allowed target.
- Real game test: Prism/game traffic uses the same server profile and a real
  game target already covered by `allowed_targets`; this still requires user
  coordination and cannot be proven by the echo verifier alone.

Only the first layer is fully provable on a disconnected development machine.
The VPS listener, cloud firewall, public UDP path, deployed PSK, controlled echo
endpoint, and real game behavior remain checks against the actual deployment.

## Output to Share

When asking for help, provide:

- The exact command you ran.
- The full `verify-server.sh` output after reviewing it.
- The `verify-tgp-e2e.sh` command and output, with PSK removed.
- Whether the VPS cloud security group allows inbound UDP on `server.listen`.
- The Prism/Core versions involved, if testing from Prism.
- Any client-side error text with secrets removed.

Never share `tgp.auth.psk`. The verifier redacts common PSK forms, but review
the output before posting it publicly. You may redact public IPs, account IDs,
hostnames, or game target names if needed; keep the UDP port, deployment mode,
validation status, and `allowed_targets` shape visible enough to diagnose.
