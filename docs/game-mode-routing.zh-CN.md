# 游戏模式路由

[English](game-mode-routing.md)

手动添加的程序是一等路由配置。在进程归属识别成功时，它可以覆盖特殊启动器和
反作弊包装进程场景。

## 策略

- 手动配置拥有较高优先级。
- Steam 本体不会被当成游戏进程。
- Steam 子进程游戏，以及 `steamapps/common` 下的可执行文件，可以作为游戏配置建议。
- Steam 游戏库扫描会解析 `libraryfolders.vdf` 和 `appmanifest_*.acf`，再由 Prism 让用户确认添加。
- 游戏 UDP 默认走 TGP。
- 游戏 TCP 默认使用 `auto`；Core 不代理 TCP。登录、商店、下载等 TCP 代理流量由
  Prism/Xray 负责。

## Legacy 选择性路由安全语义

当前基于目标 CIDR 的 TUN 路径只是 legacy preview，并非按进程隔离接管。PID 查询
失败时，只要配置中存在依赖进程身份的启用游戏配置、Steam 子进程策略或进程名 TGP
规则，Core 就会阻止较低优先级 CIDR/default TGP 兜底，不会猜测未知包属于已选游戏。
只有完全由进程无关 CIDR TGP 规则组成的配置，才允许未知进程包显式进入 TGP；代价
是访问该目标的所有进程都可能进入 TGP。数据包一旦被接管，Core 不会把 `direct`
决策重新注入原生路径，因此该情况保持 fail-closed。

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
