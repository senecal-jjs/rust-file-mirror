//! The menu bar app's shell (macOS): draws `view::MenuModel`s and runs commands.
//! What the menu says is decided in the library; this only does the macOS side.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use mirror_core::config::{self, Config};
use mirror_core::{Error, control, service};
use rfm_tray::icons::{self, BUSY_FRAMES};
use rfm_tray::state::{Connection, Input, TrayState};
use rfm_tray::view::{Command, IconState, MenuModel, Row, Shape, view};
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tokio::sync::mpsc;
use tray_icon::menu::{IsMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// How often relative times ("2 min ago") are refreshed with nothing else happening.
const TICK: Duration = Duration::from_secs(30);
/// How fast the busy icon turns.
const FRAME: Duration = Duration::from_millis(125);
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);

enum UserEvent {
    Daemon(Box<Input>),
    Menu(MenuId),
}

/// A command for the daemon, sent by the background thread.
enum DaemonRequest {
    Send(&'static str),
}

pub fn main() {
    let config_path = std::env::var_os("RFM_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(config::default_path);
    let config = Config::load(&config_path);

    if std::env::args().any(|arg| arg == "--status") {
        print_status(&config);
        return;
    }

    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    // A menu bar app: no Dock icon, no app menu.
    event_loop.set_activation_policy(ActivationPolicy::Accessory);

    let proxy = Mutex::new(event_loop.create_proxy());
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = proxy
            .lock()
            .expect("proxy lock")
            .send_event(UserEvent::Menu(event.id));
    }));

    let mut state = TrayState::new(
        config
            .as_ref()
            .ok()
            .map(|c| c.local.root.display().to_string()),
    );
    state.service_installed = service::is_installed(service::DAEMON_LABEL);

    let requests = match &config {
        Ok(config) => Some(spawn_daemon_thread(
            control::socket_path(config),
            event_loop.create_proxy(),
        )),
        Err(e) => {
            state.apply(
                Input::Lost(Connection::Unconfigured(e.to_string())),
                SystemTime::now(),
            );
            None
        }
    };
    let ctx = Context {
        config_path,
        root: config.ok().map(|c| c.local.root),
        requests,
    };

    let mut renderer: Option<Renderer> = None;
    let mut frame = 0usize;
    let mut next_frame = Instant::now();

    event_loop.run(move |event, _, control_flow| {
        let now = SystemTime::now();
        match event {
            // macOS wants the status item created once the loop is running.
            Event::NewEvents(StartCause::Init) => {
                renderer = Some(Renderer::new(&view(&state, now)));
            }
            Event::NewEvents(StartCause::ResumeTimeReached { .. }) => frame += 1,
            Event::UserEvent(UserEvent::Daemon(input)) => {
                if matches!(*input, Input::Connected(_) | Input::Lost(_)) {
                    state.service_installed = service::is_installed(service::DAEMON_LABEL);
                }
                state.apply(*input, now);
            }
            Event::UserEvent(UserEvent::Menu(id)) => {
                let command = renderer.as_ref().and_then(|r| r.commands.get(&id).cloned());
                if let Some(command) = command {
                    if command == Command::Quit {
                        *control_flow = ControlFlow::Exit;
                        return;
                    }
                    ctx.run(&command);
                }
            }
            _ => return,
        }

        let model = view(&state, now);
        if let Some(renderer) = &mut renderer {
            renderer.render(&model, frame);
        }
        // Animate while busy; otherwise wake only to refresh relative times.
        *control_flow = if model.icon == IconState::Busy {
            if Instant::now() >= next_frame {
                next_frame = Instant::now() + FRAME;
            }
            ControlFlow::WaitUntil(next_frame)
        } else {
            ControlFlow::WaitUntil(Instant::now() + TICK)
        };
    });
}

/// `rfm-tray --status`: prints the menu the tray would show right now, without
/// drawing anything. For diagnosing the tray from a terminal.
fn print_status(config: &mirror_core::Result<Config>) {
    let now = SystemTime::now();
    let mut state = TrayState::new(
        config
            .as_ref()
            .ok()
            .map(|c| c.local.root.display().to_string()),
    );
    state.service_installed = service::is_installed(service::DAEMON_LABEL);
    let input = match config {
        Err(e) => Input::Lost(Connection::Unconfigured(e.to_string())),
        Ok(config) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            match runtime.block_on(control::subscribe(&control::socket_path(config))) {
                Ok((hello, _)) => Input::Connected(hello),
                Err(Error::DaemonNotRunning(_)) => Input::Lost(Connection::NotRunning),
                Err(Error::DaemonIncompatible(reply)) => {
                    Input::Lost(Connection::Incompatible(reply))
                }
                Err(e) => Input::Lost(Connection::Failed(e.to_string())),
            }
        }
    };
    state.apply(input, now);
    print!("{}", view(&state, now).to_text());
}

/// Runs the daemon connection on its own thread: a subscriber that reconnects
/// with backoff, and a queue of commands to send.
fn spawn_daemon_thread(
    socket: PathBuf,
    proxy: EventLoopProxy<UserEvent>,
) -> mpsc::UnboundedSender<DaemonRequest> {
    let (tx, mut rx) = mpsc::unbounded_channel::<DaemonRequest>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
            let commands_socket = socket.clone();
            tokio::spawn(async move {
                while let Some(DaemonRequest::Send(command)) = rx.recv().await {
                    match control::request(&commands_socket, command).await {
                        Ok(reply) => eprintln!("{command}: {}", reply.trim()),
                        Err(e) => eprintln!("{command}: {e}"),
                    }
                }
            });
            subscribe_forever(&socket, &proxy).await;
        });
    });
    tx
}

async fn subscribe_forever(socket: &Path, proxy: &EventLoopProxy<UserEvent>) {
    let send = |input| proxy.send_event(UserEvent::Daemon(Box::new(input))).is_ok();
    let mut retry = RETRY_MIN;
    loop {
        let lost = match control::subscribe(socket).await {
            Ok((hello, mut events)) => {
                retry = RETRY_MIN;
                if !send(Input::Connected(hello)) {
                    return; // the UI is gone
                }
                loop {
                    match events.next().await {
                        Ok(Some(event)) => {
                            if !send(Input::Event(event)) {
                                return;
                            }
                        }
                        Ok(None) | Err(_) => break Connection::NotRunning,
                    }
                }
            }
            Err(Error::DaemonNotRunning(_)) => Connection::NotRunning,
            Err(Error::DaemonIncompatible(reply)) => Connection::Incompatible(reply),
            Err(e) => Connection::Failed(e.to_string()),
        };
        if !send(Input::Lost(lost)) {
            return;
        }
        tokio::time::sleep(retry).await;
        retry = (retry * 2).min(RETRY_MAX);
    }
}

/// Everything commands need.
struct Context {
    config_path: PathBuf,
    root: Option<PathBuf>,
    requests: Option<mpsc::UnboundedSender<DaemonRequest>>,
}

impl Context {
    fn send(&self, command: &'static str) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(DaemonRequest::Send(command));
        }
    }

    fn run(&self, command: &Command) {
        match command {
            Command::Sync => self.send("sync"),
            Command::Backup => self.send("backup"),
            Command::StopDaemon => self.send("stop"),
            Command::OpenFolder => {
                if let Some(root) = &self.root {
                    spawn(Process::new("open").arg(root));
                }
            }
            Command::Reveal(rel) => {
                if let Some(root) = &self.root {
                    // An offloaded file is only its placeholder now.
                    let path = root.join(rel);
                    let stub = root.join(format!("{rel}{}", mirror_core::placeholder::SUFFIX));
                    let target = if !path.exists() && stub.exists() {
                        stub
                    } else {
                        path
                    };
                    spawn(Process::new("open").arg("-R").arg(target));
                }
            }
            Command::OpenDashboard => self.in_terminal("tui"),
            Command::SetUp => self.in_terminal("init"),
            Command::StartDaemon => {
                launchctl(&["kickstart", &service::service_target(service::DAEMON_LABEL)])
            }
            Command::RestartDaemon => launchctl(&[
                "kickstart",
                "-k",
                &service::service_target(service::DAEMON_LABEL),
            ]),
            Command::InstallService => spawn(
                Process::new(rfm_path())
                    .args(["service", "install"])
                    .env("RFM_CONFIG", &self.config_path),
            ),
            Command::Quit => {}
        }
    }

    /// Opens Terminal running `rfm <subcommand>` against the same config.
    fn in_terminal(&self, subcommand: &str) {
        let line = format!(
            "RFM_CONFIG={} {} {subcommand}",
            shell_quote(&self.config_path.to_string_lossy()),
            shell_quote(&rfm_path().to_string_lossy())
        );
        let script = format!(
            "tell application \"Terminal\"\n  activate\n  do script \"{}\"\nend tell",
            line.replace('\\', "\\\\").replace('"', "\\\"")
        );
        spawn(Process::new("osascript").arg("-e").arg(script));
    }
}

/// `rfm` beside this binary (they ship together), else whatever `PATH` finds.
fn rfm_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| service::sibling(&exe, "rfm"))
        .unwrap_or_else(|| PathBuf::from("rfm"))
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

fn launchctl(args: &[&str]) {
    spawn(Process::new("launchctl").args(args));
}

/// Starts a helper process without waiting for it; failures are logged.
fn spawn(command: &mut Process) {
    if let Err(e) = command.spawn() {
        eprintln!("couldn't run {:?}: {e}", command.get_program());
    }
}

/// A drawn menu item, mirroring a `Row`.
enum Item {
    Info(MenuItem),
    Separator,
    Action(MenuItem),
    Submenu(Submenu, Vec<Item>),
}

struct Renderer {
    tray: TrayIcon,
    shape: Vec<Shape>,
    items: Vec<Item>,
    commands: HashMap<MenuId, Command>,
    drawn_icon: Option<(IconState, usize)>,
    tooltip: String,
}

impl Renderer {
    fn new(model: &MenuModel) -> Self {
        let tray = TrayIconBuilder::new()
            .with_icon_templated(icon(model.icon, 0))
            .with_tooltip(&model.tooltip)
            .build()
            .expect("creating the menu bar item");
        let mut renderer = Self {
            tray,
            shape: Vec::new(),
            items: Vec::new(),
            commands: HashMap::new(),
            drawn_icon: Some((model.icon, 0)),
            tooltip: model.tooltip.clone(),
        };
        renderer.rebuild(model);
        renderer
    }

    /// Updates labels in place while the menu's shape holds (so an open menu stays
    /// open as progress and times tick), and rebuilds it when rows come or go.
    fn render(&mut self, model: &MenuModel, frame: usize) {
        if model.shape() == self.shape {
            update(&self.items, &model.rows);
        } else {
            self.rebuild(model);
        }

        let frame = if model.icon == IconState::Busy {
            frame % BUSY_FRAMES
        } else {
            0
        };
        if self.drawn_icon != Some((model.icon, frame)) {
            let _ = self.tray.set_icon_templated(Some(icon(model.icon, frame)));
            self.drawn_icon = Some((model.icon, frame));
        }
        if self.tooltip != model.tooltip {
            let _ = self.tray.set_tooltip(Some(&model.tooltip));
            self.tooltip.clone_from(&model.tooltip);
        }
    }

    fn rebuild(&mut self, model: &MenuModel) {
        let menu = Menu::new();
        self.commands.clear();
        self.items = build(&model.rows, &mut self.commands);
        for item in &self.items {
            let _ = match item.as_menu_item() {
                Some(native) => menu.append(native),
                None => menu.append(&PredefinedMenuItem::separator()),
            };
        }
        self.tray.set_menu(Some(Box::new(menu)));
        self.shape = model.shape();
    }
}

impl Item {
    /// The native item to append; `None` for a separator, which is stateless and
    /// gets a fresh native item wherever it's appended.
    fn as_menu_item(&self) -> Option<&dyn IsMenuItem> {
        match self {
            Item::Info(item) | Item::Action(item) => Some(item),
            Item::Submenu(submenu, _) => Some(submenu),
            Item::Separator => None,
        }
    }
}

fn build(rows: &[Row], commands: &mut HashMap<MenuId, Command>) -> Vec<Item> {
    rows.iter()
        .map(|row| match row {
            Row::Info(text) => Item::Info(MenuItem::new(text, false, None)),
            Row::Separator => Item::Separator,
            Row::Action {
                command,
                label,
                enabled,
            } => {
                let item = MenuItem::new(label, *enabled, None);
                commands.insert(item.id().clone(), command.clone());
                Item::Action(item)
            }
            Row::Submenu { label, items } => {
                let submenu = Submenu::new(label, true);
                let children = build(items, commands);
                for child in &children {
                    append(&submenu, child);
                }
                Item::Submenu(submenu, children)
            }
        })
        .collect()
}

fn append(submenu: &Submenu, item: &Item) {
    let _ = match item.as_menu_item() {
        Some(native) => submenu.append(native),
        None => submenu.append(&PredefinedMenuItem::separator()),
    };
}

fn update(items: &[Item], rows: &[Row]) {
    for (item, row) in items.iter().zip(rows) {
        match (item, row) {
            (Item::Info(item), Row::Info(text)) => item.set_text(text),
            (Item::Action(item), Row::Action { label, enabled, .. }) => {
                item.set_text(label);
                item.set_enabled(*enabled);
            }
            (Item::Submenu(submenu, children), Row::Submenu { label, items }) => {
                submenu.set_text(label);
                update(children, items);
            }
            _ => {}
        }
    }
}

fn icon(state: IconState, frame: usize) -> Icon {
    Icon::from_rgba(icons::rgba(state, frame), icons::SIZE, icons::SIZE)
        .expect("icons are well-formed")
}
