# Game Mode Routing

[中文说明](game-mode-routing.zh-CN.md)

Manual program entries are first-class routing profiles. They cover games with
unusual launchers and anti-cheat wrappers when process attribution succeeds.

## Policy

- Manual profiles have high priority.
- Steam itself is not treated as a game process.
- Steam child games and executables under `steamapps/common` may be suggested as
  game profiles.
- Steam library scanning parses `libraryfolders.vdf` and `appmanifest_*.acf`
  before Prism asks the user to add a profile.
- Game UDP defaults to TGP.
- Game TCP defaults to `auto`; Core does not proxy TCP traffic. Prism/Xray owns
  login, store, download, and other TCP proxy flows.

## Legacy Selective-Route Safety

The current destination-CIDR TUN path is a legacy preview, not process-isolated
capture. When PID lookup fails and any enabled game profile, Steam child policy,
or process-name TGP rule depends on process identity, Core blocks lower-priority
CIDR/default TGP fallback. It does not guess that the unknown packet belongs to
the selected game. A configuration containing only process-independent CIDR
TGP rules may explicitly accelerate an unknown-process packet, but every process
contacting that destination can then enter TGP. A `direct` decision is not
re-injected by Core and therefore remains fail-closed after capture.

## Core JSON Example

```json
{
  "client": {
    "routing": {
      "default_action": "direct",
      "game_profiles": [
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
  }
}
```
