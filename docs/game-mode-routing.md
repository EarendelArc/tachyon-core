# Game Mode Routing

[中文说明](game-mode-routing.zh-CN.md)

Manual program entries are first-class routing profiles. This prevents games
with unusual launchers, anti-cheat wrappers, or missing process metadata from
falling back to generic routing.

## Policy

- Manual profiles have the highest priority.
- Steam itself is not treated as a game process.
- Steam child games and executables under `steamapps/common` may be treated as
  game traffic.
- Game UDP defaults to TGP.
- Game TCP defaults to auto, allowing login and store traffic to use Xray or
  direct routing according to normal rules.

## Example

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
