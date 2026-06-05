# Tachyon Core 架构

[English](architecture.md)

Core 有四个主要边界：

1. TUN 栈：接管数据包并还原流元数据。
2. PID tracking：把网络流映射到进程元数据。
3. 路由引擎：对游戏相关流量决定 TGP、直连或丢弃。
4. TGP 传输：把选中的 UDP 游戏包发送到 Relay。

游戏路由优先级：

```text
手动配置 > 启动器子进程 > 已知游戏配置 > 进程/Geo 规则 > 默认规则
```

TGP 只接收已经被路由引擎判定为游戏 UDP 的流量。它不关心该决策来自手动规则、Steam，
还是未来的其他启动器 provider。Xray 与 TCP 代理编排被刻意排除在 Core 之外，由 Prism 负责。
