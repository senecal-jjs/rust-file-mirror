# Plan: a macOS menu bar app for rfm

A small menu bar app, `rfm-tray`, that shows what the `rfm watch` daemon is doing and
offers the common commands, so day-to-day use doesn't need a terminal.

## Scope

- **macOS only**, matching current releases (the Linux target in `release.yml` is
  commented out).
- **A bare binary**, shipped in the existing Homebrew cask next to `rfm`. No `.app`
  bundle, so no code signing or notarization for now.
- **A client of the daemon, not a second daemon.** Syncing and backups stay in the
  headless `rfm watch` that launchd runs. The tray only shows state and sends
  commands; if it quits or crashes, syncing carries on.

## What it looks like

```
 ◉   menu bar icon: idle · syncing · error · not running
 ┌───────────────────────────────────────┐
 │ ● Up to date · synced 2 min ago       │  status (disabled item)
 │   Backup: 3 h ago (snapshot ab12cd34) │  only if backups are used
 │   ↑ 2 transfers · photo.jpg 45%       │  only while syncing
 ├───────────────────────────────────────┤
 │ Sync Now                     ⌘S       │  → control "sync"
 │ Back Up Now                           │  → control "backup"
 │ Open Folder                           │  → open <root>
 │ Open Dashboard                        │  → Terminal running `rfm tui`
 │ Recent                              ▸ │  last 8 completed actions;
 │    ↑ report.pdf                       │    click reveals in Finder
 │    ↓ notes.md                         │
 ├───────────────────────────────────────┤
 │ Start Daemon  /  Stop Daemon          │  see "Running the daemon"
 │ Quit rfm Tray                         │
 └───────────────────────────────────────┘
```

| State | Icon | Status line |
|---|---|---|
| Idle, last sync OK | plain | `● Up to date · synced 2 min ago` |
| Syncing or backing up | animated, or a badge | `● Syncing (file change) · 12 s` |
| Last sync or backup failed | with a warning mark | `● Last sync failed: <first line>` (the full error in a submenu) |
| Daemon not running | dimmed | `○ Daemon not running` (offers **Start Daemon**) |
| Not configured | dimmed | `○ Not set up: run rfm init` |

Icons are monochrome **template images** (`set_icon_as_template`), so macOS adapts them
to light and dark menu bars. Each state needs 1x and 2x PNGs at 18–22 pt, embedded with
`include_bytes!`.

## Architecture

```
 main thread (AppKit)                      background thread (tokio)
 ┌────────────────────────────┐            ┌──────────────────────────────┐
 │ tao EventLoop              │  proxy     │ subscriber: connect to       │
 │  ├ TrayIcon + muda Menu    │◄───────────│  <root>/.mirror/daemon.sock, │
 │  ├ TrayState (pure)        │ UiEvent /  │  send "subscribe", decode    │
 │  └ render(view) on change  │ Connected/ │  JSON lines, reconnect with  │
 │                            │ Disconnected│  backoff (1 s → 30 s)       │
 │ menu click ───────────────►│───────────►│ commands: one connection per │
 │                            │  channel   │  request ("sync", "backup",  │
 └────────────────────────────┘            │  "stop"), reply logged       │
                                           └──────────────────────────────┘
```

- **UI libraries:** `tray-icon` and `muda` (the Tauri team's tray and native-menu
  crates) with `tao` for the event loop. AppKit requires the menu and status item on
  the main thread; `tao` owns it.
- **No Dock icon:** at startup, `ActivationPolicy::Accessory` (via `tao`'s macOS
  extension) makes it a menu-bar-only app. That's what `LSUIElement` would do in an
  `.app` bundle's `Info.plist`.
- **Background thread:** a small tokio runtime holds the `subscribe` connection, the
  same protocol `rfm tui` uses, and passes events to the UI loop through
  `EventLoopProxy`. Menu clicks go the other way over a channel.
- **Split logic from shell.** `TrayState::apply(event)` is a pure reducer, like
  `tui::app::App`. `TrayState::view() -> MenuModel` describes the menu: item texts,
  enabled flags, icon state. A thin shell applies a `MenuModel` to the real `muda`
  items (`set_text`, `set_enabled`) and the icon. Everything except the shell is
  testable without a display.
- **Time-based text** ("2 min ago") is refreshed by a 30-second timer, not only by
  events.

## Sharing the protocol

The tray decodes the same JSON lines as `rfm tui`. Today those types live inside the
CLI binary (`crates/mirror-cli/src/events.rs`), so they move:

- **To `mirror-core`, in a new `control` module:**
  - the data types `Trigger`, `LogLevel`, `LastSync`, `LastBackup`, `BackupSummary`,
    `Snapshot` and `UiEvent`;
  - `socket_path(&Config)`;
  - a small async client: `request(config, command) -> String` and
    `subscribe(config) -> stream of UiEvent`.
- **Stays in the CLI:** `Hub`, `HubReporter` and the tracing writer, which are about
  producing events, not reading them. They import the moved types.
- `mirror-core` already owns `SyncOutcome`, `ActionKind` and `Config`, which these types
  use, so the tray depends only on `mirror-core`. That pulls in the AWS SDK at compile
  time even though the tray never talks to S3. It's acceptable for one extra binary in a
  workspace that already builds it. If build times or binary size start to matter, the
  types could later move into a tiny `rfm-control` crate.
- **Compatibility:** the status snapshot already tolerates missing fields, so a newer
  tray works with an older daemon. A daemon too old to support `subscribe` gets the
  status line `○ Daemon is older than this tray; restart it`.

## Running the daemon

The cask ships only the `rfm` binary, with no service definition, and `brew services`
manages formulae rather than casks. So a tray that wants to start the daemon needs a
service it can rely on. This adds a small CLI command:

```
rfm service install [--tray]   # write and load LaunchAgents
rfm service uninstall [--tray]
rfm service status
```

- **The daemon agent:** `~/Library/LaunchAgents/com.senecal-jjs.rfm.watch.plist`, which
  runs `rfm watch` with:
  - `RunAtLoad`;
  - `KeepAlive = { SuccessfulExit = false }`, so it restarts after a crash but not
    after a clean stop (`rfm watch` exits 0 when asked to stop);
  - logs to `~/Library/Logs/rfm/watch.log`.
- **The tray agent (`--tray`):** `com.senecal-jjs.rfm.tray.plist` runs `rfm-tray` at
  login.
- The agents point at the binaries' absolute paths, resolved from
  `std::env::current_exe` at install time and re-resolved by `install` after an
  upgrade.
- **The tray's daemon items:**
  - **Start Daemon:** if the agent is installed, `launchctl kickstart gui/<uid>/<label>`.
    Otherwise the item reads **Install Background Service…**, which runs
    `rfm service install` and then starts it.
  - **Stop Daemon:** sends `stop` over the socket. Because the exit is clean, launchd
    doesn't restart it until the next login or **Start Daemon**.
- The README's "run it as a background service" section changes to
  `rfm service install`.

## Other commands

| Item | Does |
|---|---|
| Open Folder | `open <root>` |
| Open Dashboard | `osascript` tells Terminal to run `rfm tui` (Terminal, not the user's preferred terminal app, for now) |
| Recent ▸ item | `open -R <root>/<path>` (reveal in Finder); disabled for deletions |
| Quit rfm Tray | exits the tray only; says so in the item's tooltip |

## Edge cases

| Case | Behavior |
|---|---|
| No config / root missing | "Not set up" state; only **Open Dashboard** (to run `rfm init`) and **Quit** |
| Daemon restarts or the Mac sleeps | The subscriber drops, shows "not running", and reconnects with backoff. A fresh hello restores state. |
| Socket path too long (over ~104 bytes, a macOS limit `rfm watch` already has) | Status shows the error and the root path, so it's clear why |
| Command sent while disconnected | Item is disabled; never queued |
| Event stream lags | The daemon already sends a "display fell behind" log line; the tray just keeps the latest state |
| Several roots | Out of scope: one config, one root, as for the CLI |

## Phases

1. **Protocol move (no behavior change).** Move the types and socket client into
   `mirror_core::control`. The CLI uses them, and `rfm tui` and `rfm daemon` keep
   working. Tests: the existing event round-trip tests move with the types; a socket
   client test runs against a fake `UnixListener`.
2. **Tray state and menu model.** `TrayState`, `MenuModel`, icon states and relative
   times. Tests: unit tests feeding event sequences (hello, sync started and finished,
   failure, backup, disconnect, reconnect) and snapshot tests of the menu model with
   `insta`, like the TUI's.
3. **The `rfm-tray` binary.** A `crates/rfm-tray` crate with the `tao` event loop,
   tray icon, `muda` menu, background subscriber and commands, Accessory activation
   policy, and the template icons. Checked by hand with a checklist: each state shows
   correctly; each command works; the daemon restarting and the Mac sleeping recover;
   there's no Dock icon.
4. **`rfm service` and the tray's daemon controls.** The LaunchAgent plists (generated,
   so tests can compare them), install/uninstall/status, and Start/Stop/Install in the
   tray. Tests: plist contents, and that uninstall removes only the agents it wrote.
5. **Release and docs.** `release.yml` builds `-p rfm-tray` for both architectures and
   tars it beside `rfm`; the cask gains `binary "rfm-tray"`. README sections on the
   tray and `rfm service`.

Later, not in this plan:
- notifications for failed syncs or backups and for conflicts (`osascript display
  notification`, or `mac-notification-sys`);
- **Pause/Resume Syncing**, which needs daemon commands;
- a signed `.app` bundle;
- Linux (`ksni` or `tray-icon` with AppIndicator).

## Size

| Piece | Rough size |
|---|---|
| Protocol move | ~150 lines moved, ~80 new (client) |
| `TrayState` and `MenuModel`, with tests | ~400 |
| `rfm-tray` shell | ~300 |
| `rfm service` | ~200 with tests |
| Icons | 4 states × 2 scales, design work |
| CI and cask changes | ~20 lines of YAML |

## Decisions

1. **macOS only, bare binary**: decided.
2. **Pause/Resume**: assumed later, since it needs new daemon commands. Say so if it
   should be in the first version.
3. **Start Daemon**: assumed in scope, through `rfm service install` LaunchAgents
   rather than spawning `rfm watch` from the tray, so the daemon keeps running when the
   tray quits and restarts after crashes. Say so if the tray should just show "not
   running" instead.
