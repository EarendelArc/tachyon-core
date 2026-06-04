# Tachyon Core 架构

[English](architecture.md)

Core 有四个主要边界：

1. TUN 栈：接管数据包并还原流元数据。
2. PID tracking：把网络流映射到进程元数据。
3. 路由引擎：决定直连、Xray 或 TGP。
4. 传输 runner：执行最终选择的流量路径。

游戏路由优先级：

```text
手动配置 > 启动器子进程 > 已知游戏配置 > 进程/Geo 规则 > 默认规则
```

TGP 只接收已经被路由引擎判定为游戏 UDP 的流量。它不关心该决策来自手动规则、Steam，还是未来的其他启动器 provider。
