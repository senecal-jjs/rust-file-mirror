//! launchd LaunchAgents for running rfm in the background on macOS: the daemon
//! (`rfm watch`) and, optionally, the menu bar app. `rfm service` writes and loads
//! them; the menu bar app reads them to know whether it can start the daemon.

use std::path::{Path, PathBuf};

pub const DAEMON_LABEL: &str = "com.senecal-jjs.rfm.watch";
pub const TRAY_LABEL: &str = "com.senecal-jjs.rfm.tray";

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn agents_dir() -> PathBuf {
    home().join("Library/LaunchAgents")
}

pub fn plist_path(label: &str) -> PathBuf {
    agents_dir().join(format!("{label}.plist"))
}

/// Where an agent's output goes.
pub fn log_path(label: &str) -> PathBuf {
    let name = label.rsplit('.').next().unwrap_or(label);
    home().join("Library/Logs/rfm").join(format!("{name}.log"))
}

pub fn is_installed(label: &str) -> bool {
    plist_path(label).is_file()
}

/// What an agent runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub label: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Extra environment, such as `RFM_CONFIG` when the config isn't in the
    /// default place.
    pub env: Vec<(String, String)>,
    pub log: PathBuf,
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

impl Agent {
    /// The property list launchd loads. The agent starts at login and is restarted
    /// if it crashes, but not after a clean exit (`rfm watch` exits 0 when asked to
    /// stop, the menu bar app when quit), so stopping it on purpose sticks until
    /// the next login or an explicit start.
    pub fn plist(&self) -> String {
        let mut arguments = format!(
            "        <string>{}</string>\n",
            xml_escape(&self.program.to_string_lossy())
        );
        for arg in &self.args {
            arguments += &format!("        <string>{}</string>\n", xml_escape(arg));
        }
        let env = if self.env.is_empty() {
            String::new()
        } else {
            let mut entries = String::new();
            for (key, value) in &self.env {
                entries += &format!(
                    "        <key>{}</key>\n        <string>{}</string>\n",
                    xml_escape(key),
                    xml_escape(value)
                );
            }
            format!("    <key>EnvironmentVariables</key>\n    <dict>\n{entries}    </dict>\n")
        };
        let log = xml_escape(&self.log.to_string_lossy());
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{arguments}    </array>
{env}    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
            label = xml_escape(&self.label),
        )
    }
}

/// The `gui/<uid>` launchd domain of the current user.
pub fn gui_domain() -> String {
    format!("gui/{}", unsafe { libc_getuid() })
}

/// `gui/<uid>/<label>`, as `launchctl kickstart` and `print` take it.
pub fn service_target(label: &str) -> String {
    format!("{}/{label}", gui_domain())
}

unsafe extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// The other rfm binary next to `exe` (they're installed side by side), if it's
/// there.
pub fn sibling(exe: &Path, name: &str) -> Option<PathBuf> {
    let path = exe.parent()?.join(name);
    path.is_file().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Agent {
        Agent {
            label: DAEMON_LABEL.into(),
            program: PathBuf::from("/opt/homebrew/bin/rfm"),
            args: vec!["watch".into()],
            env: vec![("RFM_CONFIG".into(), "/Users/me/rfm & co/config.toml".into())],
            log: PathBuf::from("/Users/me/Library/Logs/rfm/watch.log"),
        }
    }

    #[test]
    fn plist_runs_the_program_and_restarts_only_after_crashes() {
        let plist = agent().plist();
        assert!(plist.contains("<string>com.senecal-jjs.rfm.watch</string>"));
        assert!(
            plist
                .contains("<string>/opt/homebrew/bin/rfm</string>\n        <string>watch</string>")
        );
        assert!(plist.contains("<key>SuccessfulExit</key>\n        <false/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(
            plist.contains("<string>/Users/me/rfm &amp; co/config.toml</string>"),
            "escaped"
        );
        assert_eq!(plist.matches("watch.log").count(), 2, "stdout and stderr");
    }

    #[test]
    fn plist_omits_an_empty_environment() {
        let mut agent = agent();
        agent.env.clear();
        assert!(!agent.plist().contains("EnvironmentVariables"));
    }

    /// `plutil` is the authority on what launchd will accept.
    #[test]
    fn plist_is_valid_xml_plist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.plist");
        std::fs::write(&path, agent().plist()).unwrap();
        let status = std::process::Command::new("plutil")
            .arg("-lint")
            .arg(&path)
            .status();
        if let Ok(status) = status {
            assert!(status.success());
        }
    }

    #[test]
    fn paths_and_targets() {
        assert!(
            plist_path(TRAY_LABEL).ends_with("Library/LaunchAgents/com.senecal-jjs.rfm.tray.plist")
        );
        assert!(log_path(DAEMON_LABEL).ends_with("Library/Logs/rfm/watch.log"));
        assert!(service_target(DAEMON_LABEL).starts_with("gui/"));
        assert!(service_target(DAEMON_LABEL).ends_with("/com.senecal-jjs.rfm.watch"));
    }
}
