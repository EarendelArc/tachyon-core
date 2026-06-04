# Game Mode Routing

[中文说明](game-mode-routing.zh-CN.md)

Manual program entries are first-class routing profiles. They prevent games with
unusual launchers, anti-cheat wrappers, or missing process metadata from falling
back to generic routing.

## Policy

- Manual profiles have high priority.
- Steam itself is not treated as a game process.
- Steam child games and executables under `steamapps/common` may be suggested as
  game profiles.
- Steam library scanning parses `libraryfolders.vdf` and `appmanifest_*.acf`
  before Prism asks the user to add a profile.
- Game UDP defaults to TGP.
- Game TCP defaults to `auto`, allowing login, store, and download traffic to
  use Xray or direct routing according to normal rules.

## Store Example

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
