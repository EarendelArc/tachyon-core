# Tachyon Core Architecture

[中文说明](architecture.zh-CN.md)

Core has four major boundaries:

1. TUN stack: captures packets and reconstructs flow metadata.
2. PID tracking: maps flows to process metadata.
3. Routing engine: decides TGP, direct, or drop for game-related flows.
4. TGP transport: carries selected UDP game packets to the relay.

Game routing priority:

```text
manual profile > launcher child process > known game profile > process/geo rule > default
```

TGP receives only traffic that the routing engine has classified as game UDP.
It does not know whether the decision came from a manual rule, Steam, or a
future launcher provider. Xray and TCP proxy orchestration are intentionally
outside Core and belong to Prism.
