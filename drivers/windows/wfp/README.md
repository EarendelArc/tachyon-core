# Tachyon Windows WFP Driver

This is an independent KMDF/WFP driver target. It is not linked into the Go
binary and the UI has no device access. The device ACL grants access only to
LocalSystem and the restricted `TachyonHelper` Service SID.

The checked-in source is a development milestone. A successful WDK build is
not evidence of signing, installation, runtime safety, latency, or game-path
correctness. Receive injection is absent, so the provider is deliberately
`not_ready`. See `docs/windows-wfp-dataplane.md` and
`docs/windows-wfp-dataplane.zh-CN.md` before any VM test.

Chinese: `README.zh-CN.md`.
