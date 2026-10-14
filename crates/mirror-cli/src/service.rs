//! `rfm service`: run the daemon (and optionally the menu bar app) in the
//! background on macOS, as launchd LaunchAgents. The Homebrew cask ships bare
//! binaries with no service definition, so rfm installs its own.

use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Subcommand;
use mirror_core::config::{self, Config};
use mirror_core::control;
use mirror_core::service::{self, Agent, DAEMON_LABEL, TRAY_LABEL};

#[derive(Subcommand)]
pub(crate) enum ServiceCmd {
    /// Run `rfm watch` in the background, starting at login (a launchd LaunchAgent)
    Install {
        /// Also start the menu bar app (rfm-tray) at login
        #[arg(long)]
        tray: bool,
    },
    /// Stop and remove the background daemon
    Uninstall {
        /// Also remove the menu bar app's login item
        #[arg(long)]
        tray: bool,
    },
    /// Show what's installed and running
    Status,
}

pub(crate) async fn run(config_path: &Path, cmd: ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Install { tray } => install(config_path, tray).await,
        ServiceCmd::Uninstall { tray } => uninstall(tray),
        ServiceCmd::Status => status(config_path).await,
    }
}

fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the rfm binary")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

/// `RFM_CONFIG` for the agent, when the config isn't where every rfm program looks
/// by default: launchd starts agents without the shell's environment.
fn config_env(config_path: &Path) -> Vec<(String, String)> {
    let absolute = std::path::absolute(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    if absolute == config::default_path() {
        Vec::new()
    } else {
        vec![("RFM_CONFIG".into(), absolute.to_string_lossy().into_owned())]
    }
}

pub(crate) fn daemon_agent(exe: &Path, config_path: &Path) -> Agent {
    Agent {
        label: DAEMON_LABEL.into(),
        program: exe.to_path_buf(),
        args: vec!["watch".into()],
        env: config_env(config_path),
        log: service::log_path(DAEMON_LABEL),
    }
}

pub(crate) fn tray_agent(tray_exe: &Path, config_path: &Path) -> Agent {
    Agent {
        label: TRAY_LABEL.into(),
        program: tray_exe.to_path_buf(),
        args: Vec::new(),
        env: config_env(config_path),
        log: service::log_path(TRAY_LABEL),
    }
}

/// Whether launchd has the agent loaded.
fn is_loaded(label: &str) -> bool {
    Process::new("launchctl")
        .args(["print", &service::service_target(label)])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn launchctl(args: &[&str]) -> Result<()> {
    let out = Process::new("launchctl")
        .args(args)
        .output()
        .context("running launchctl")?;
    anyhow::ensure!(
        out.status.success(),
        "launchctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// Writes the agent's plist and (re)loads it, so it starts now and at every login.
fn load(agent: &Agent) -> Result<()> {
    let path = service::plist_path(&agent.label);
    std::fs::create_dir_all(service::agents_dir())?;
    if let Some(logs) = agent.log.parent() {
        std::fs::create_dir_all(logs)?;
    }
    if is_loaded(&agent.label) {
        launchctl(&["bootout", &service::service_target(&agent.label)])?;
    }
    std::fs::write(&path, agent.plist()).with_context(|| format!("writing {}", path.display()))?;
    launchctl(&["bootstrap", &service::gui_domain(), &path.to_string_lossy()])
}

fn unload(label: &str) -> Result<bool> {
    let path = service::plist_path(label);
    if is_loaded(label) {
        launchctl(&["bootout", &service::service_target(label)])?;
    }
    if path.is_file() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(true);
    }
    Ok(false)
}

async fn install(config_path: &Path, tray: bool) -> Result<()> {
    let config = Config::load(config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;
    let exe = current_exe()?;
    let tray_exe = if tray {
        Some(
            service::sibling(&exe, "rfm-tray")
                .with_context(|| format!("rfm-tray isn't installed next to {}", exe.display()))?,
        )
    } else {
        None
    };

    // The background daemon has no terminal to ask for the passphrase.
    let saved = config.local.root.join(".mirror/passphrase");
    if !saved.is_file() {
        eprintln!(
            "warning: no saved passphrase at {}; the daemon won't be able to start. Run `rfm init` to save one.",
            saved.display()
        );
    }

    // A daemon started by hand holds the root's lock: launchd's would fail, and be
    // restarted, until it's gone.
    let socket = control::socket_path(&config);
    if !is_loaded(DAEMON_LABEL) && control::request(&socket, "status").await.is_ok() {
        println!("stopping the daemon running in the foreground so launchd can take over");
        control::request(&socket, "stop").await?;
        // The daemon removes its socket as it exits, after letting a sync in flight
        // finish; until then it still holds the root's lock.
        let deadline = Instant::now() + Duration::from_secs(120);
        while socket.exists() {
            anyhow::ensure!(
                Instant::now() < deadline,
                "the running daemon hasn't stopped yet; try again once it has"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    let agent = daemon_agent(&exe, config_path);
    load(&agent)?;
    println!(
        "daemon   installed   starts at login; logs in {}",
        agent.log.display()
    );

    if let Some(tray_exe) = tray_exe {
        let agent = tray_agent(&tray_exe, config_path);
        load(&agent)?;
        println!("tray     installed   starts at login");
    }
    Ok(())
}

fn uninstall(tray: bool) -> Result<()> {
    let labels: &[&str] = if tray {
        &[DAEMON_LABEL, TRAY_LABEL]
    } else {
        &[DAEMON_LABEL]
    };
    for label in labels {
        let name = if *label == DAEMON_LABEL {
            "daemon"
        } else {
            "tray"
        };
        if unload(label)? {
            println!("{name:<8} removed");
        } else {
            println!("{name:<8} wasn't installed");
        }
    }
    Ok(())
}

async fn status(config_path: &Path) -> Result<()> {
    for (name, label) in [("daemon", DAEMON_LABEL), ("tray", TRAY_LABEL)] {
        let state = match (service::is_installed(label), is_loaded(label)) {
            (true, true) => "installed, loaded",
            (true, false) => "installed, not loaded",
            (false, _) => "not installed",
        };
        println!("{name:<8} {state}");
    }
    let running = match Config::load(config_path) {
        Ok(config) => control::request(&control::socket_path(&config), "status")
            .await
            .is_ok(),
        Err(_) => false,
    };
    println!("running  {}", if running { "yes" } else { "no" });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agents_run_the_right_programs() {
        let daemon = daemon_agent(Path::new("/opt/homebrew/bin/rfm"), &config::default_path());
        assert_eq!(
            (daemon.label.as_str(), daemon.args.as_slice()),
            (DAEMON_LABEL, &["watch".to_string()][..])
        );
        assert!(
            daemon.env.is_empty(),
            "the default config needs no RFM_CONFIG"
        );

        let tray = tray_agent(
            Path::new("/opt/homebrew/bin/rfm-tray"),
            Path::new("/etc/rfm.toml"),
        );
        assert_eq!(tray.label, TRAY_LABEL);
        assert!(tray.args.is_empty());
        assert_eq!(
            tray.env,
            [("RFM_CONFIG".to_string(), "/etc/rfm.toml".to_string())]
        );
    }
}
