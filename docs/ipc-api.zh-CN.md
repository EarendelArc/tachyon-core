# Tachyon Core IPC API 参考

**版本：** v1.1-preview

**边界：** Core 只暴露 UDP 游戏加速状态和兼容控制。订阅解析、Xray 生命周期、Xray JSON、TCP 代理和节点选择属于 Prism；Core 不依赖 Xray。

## 认证与 authority

只有 Prism 提供 [ipc.zh-CN.md](ipc.zh-CN.md) 描述的继承匿名管道契约时，client-mode HTTP bridge 才会启用。除 preflight 外的每个请求都必须携带本进程新生成的 bearer token。请求 peer 和 `Host` header 必须匹配配置的数字 loopback endpoint。Server mode 不暴露该 API。

Core 不提供通配 CORS。浏览器请求的完整 origin 必须存在于启动 allowlist；`null` 和 `*` 被禁止。

## 端点

| Method | Path | 用途 |
| --- | --- | --- |
| `GET` | `/v1/health` | 已认证的 Core 健康检查 |
| `GET` | `/v1/routing/game-profiles` | 兼容：列出内存游戏配置 |
| `POST` | `/v1/routing/game-profiles` | 兼容：添加内存游戏配置 |
| `PUT` | `/v1/routing/game-profiles/{id}` | 兼容：替换内存游戏配置 |
| `DELETE` | `/v1/routing/game-profiles/{id}` | 兼容：删除内存游戏配置 |
| `GET` | `/v1/launchers/steam/scan?root=...` | 兼容：旧 Steam 扫描 |
| `GET` | `/v1/telemetry/sse` | 已认证的实时遥测流 |

写请求使用 JSON，最大 64 KiB，拒绝未知字段和多个 JSON value。SSE 只携带 Core 自有事件：`hello`、`telemetry`、`route_event`、`tgp_session` 和 `error`。

## 路由决策

| Action | 含义 |
| --- | --- |
| `tgp` | 将 UDP 游戏流量封装进 TGP |
| `direct` | 绕过 Core 处理 |
| `drop` | 丢弃数据包 |

Core 中不存在 `xray` action。

## HTTP 状态码

| 状态 | 含义 |
| --- | --- |
| `400` | 无效 preflight 或畸形 JSON |
| `401` | bearer token 缺失或错误 |
| `403` | Origin 不在精确 allowlist 中 |
| `405` | Endpoint 不支持该 method |
| `413` | 请求体超过 64 KiB |
| `415` | JSON 写请求的 content type 错误 |
| `421` | Peer 或 Host 不是配置的 loopback authority |
