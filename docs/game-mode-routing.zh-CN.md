# 游戏模式路由

[English](game-mode-routing.md)

手动添加的程序是一等路由配置。这样可以避免启动器特殊、反作弊包装进程复杂、或进程元数据缺失的游戏被错误回退到普通路由。

## 策略

- 手动配置拥有最高优先级。
- Steam 本体不会被当成游戏进程。
- Steam 子进程游戏，以及 `steamapps/common` 下的可执行文件，可以被识别为游戏流量。
- 游戏 UDP 默认走 TGP。
- 游戏 TCP 默认使用 auto，让登录、商店、下载等流量继续按普通规则选择 Xray 或直连。

## 示例

```yaml
routing:
  game_mode:
    manual_programs:
      - id: "cs2"
        display_name: "Counter-Strike 2"
        enabled: true
        manual: true
        match:
          process_names: ["cs2.exe"]
          steam_app_ids: [730]
        udp_policy: "tgp"
        tcp_policy: "auto"
  launchers:
    steam:
      enabled: true
      track_child_processes: true
      accelerate_game_udp: true
      accelerate_steam_downloads: false
```
