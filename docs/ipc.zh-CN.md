# Tachyon Core IPC Preview

[English](ipc.md)

Prism 通过本地 HTTP 兼容桥读取 Core 健康状态、路由遥测和 TGP 会话遥测。持久化游戏配置、订阅、Xray 配置和 Xray 生命周期仍由 Prism 负责；Core 在运行时和编译期都不依赖 Xray。

## 安全边界

该 bridge 只存在于 `client` mode，并且默认关闭。`server` mode 永远不会启动这个 GUI 控制面。Prism 启动 Core 前必须创建匿名管道、保留读取端、只允许子进程继承写入句柄，并把子进程中的数字句柄写入 `TACHYON_IPC_TOKEN_HANDLE`。Core 每次启动生成新的 256-bit session token，只向该管道写入一次，然后关闭句柄并清除环境变量。Core 不接受 argv 或环境变量中的 token，也不得记录 token。

继承管道缺失或无效时，Core 会继续运行客户端数据面，但不会打开 HTTP listener。这是 Prism 完成继承句柄接入前的预期 fail-closed 行为。

监听地址只允许精确的数字地址 `127.0.0.1` 和 `::1`。hostname、通配地址、`127.0.0.0/8` 中的其他地址、非回环地址、不匹配的 `Host` authority 和非回环 peer 都会被拒绝。包括健康检查和遥测在内的所有 endpoint 都要求 `Authorization: Bearer <session-token>`。

浏览器 CORS 默认关闭。原生 WebView 集成可以通过 `TACHYON_IPC_ALLOWED_ORIGINS` 提供逗号分隔的精确 allowlist。`null`、`*`、部分 origin、userinfo、query、fragment 和未列出的 origin 都会被拒绝。只有精确匹配 origin 且 method 受支持时才会返回 preflight。

## HTTP 限制

- JSON 写请求必须使用 `Content-Type: application/json`。
- 请求体最大 64 KiB，并且只能包含一个 JSON value。
- Header 最大 16 KiB。
- Core 设置 read、header-read、write 和 idle deadline。
- 响应使用明确的 JSON 或 SSE content type，并设置 `nosniff` 和 `no-store`。

## 兼容端点

- `GET /v1/health`
- `GET /v1/routing/game-profiles`
- `POST /v1/routing/game-profiles`
- `PUT /v1/routing/game-profiles/{id}`
- `DELETE /v1/routing/game-profiles/{id}`
- `GET /v1/launchers/steam/scan`
- `GET /v1/telemetry/sse`

路由端点仅用于兼容。新的 Prism 负责持久化配置并重新生成 `client.json`。

手动诊断时，`tachyonctl health` 只从标准输入读取 token：

```bash
tachyonctl health --addr 127.0.0.1:55123 --token-stdin
```

调用者必须从继承管道的父进程读取端取得 token；不要把 token 放入 argv、环境变量、shell history 或日志。
