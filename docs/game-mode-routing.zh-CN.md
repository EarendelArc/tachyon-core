# 游戏模式路由

[English](game-mode-routing.md)

手动添加的程序是一等路由配置。这样可以避免启动器特殊、反作弊包装进程复杂，
或者进程元数据缺失的游戏被错误回退到普通路由。

## 策略

- 手动配置拥有较高优先级。
- Steam 本体不会被当成游戏进程。
- Steam 子进程游戏，以及 `steamapps/common` 下的可执行文件，可以作为游戏配置建议。
- Steam 游戏库扫描会解析 `libraryfolders.vdf` 和 `appmanifest_*.acf`，再由 Prism 让用户确认添加。
- 游戏 UDP 默认走 TGP。
- 游戏 TCP 默认使用 `auto`；Core 不代理 TCP。登录、商店、下载等 TCP 代理流量由
  Prism/Xray 负责。

## 存储示例

```json
{
  "gameProfiles": [
    {
      "id": "cs2",
      "displayName": "Counter-Strike 2",
      "enabled": true,
      "manual": true,
      "priority": 100,
      "match": {
        "processNames": ["cs2.exe"],
        "paths": [],
        "pathPrefixes": [],
        "sha256": [],
        "steamAppIds": [730]
      },
      "udpPolicy": "tgp",
      "tcpPolicy": "auto"
    }
  ],
  "launchers": {
    "steam": {
      "enabled": true,
      "trackChildProcesses": true,
      "accelerateGameUdp": true,
      "accelerateSteamDownloads": false
    }
  }
}
```
