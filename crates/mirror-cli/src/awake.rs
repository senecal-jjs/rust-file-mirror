//! Keeping the Mac from idle-sleeping while a backup runs.
//!
//! A backup cut off by sleep is resumable, but redoing work is still waste, and a
//! long first backup on a laptop could be interrupted again and again. While a
//! `KeepAwake` lives, `caffeinate -i` holds a "prevent idle sleep" assertion.
//! Closing the lid or choosing Sleep still sleeps the Mac; only the idle timer is
//! held off. `caffeinate` also watches this process (`-w`), so a crash can never
//! leave the assertion behind.

use std::process::{Child, Command, Stdio};

pub(crate) struct KeepAwake {
    caffeinate: Option<Child>,
}

impl KeepAwake {
    /// Best effort: if `caffeinate` can't run (not macOS, say), backups go ahead
    /// without it.
    pub(crate) fn new() -> Self {
        let caffeinate = Command::new("/usr/bin/caffeinate")
            .args(["-i", "-w", &std::process::id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| tracing::debug!(error = %e, "can't hold off idle sleep"))
            .ok();
        Self { caffeinate }
    }

    #[cfg(all(test, target_os = "macos"))]
    fn pid(&self) -> Option<u32> {
        self.caffeinate.as_ref().map(Child::id)
    }
}

impl Drop for KeepAwake {
    fn drop(&mut self) {
        if let Some(child) = &mut self.caffeinate {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// `caffeinate` and `pmset` only exist on macOS.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn alive(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn holds_an_idle_sleep_assertion_until_dropped() {
        let awake = KeepAwake::new();
        let pid = awake.pid().expect("caffeinate ships with macOS");
        assert!(alive(pid));

        let assertions = Command::new("pmset")
            .args(["-g", "assertions"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&assertions.stdout);
        assert!(
            text.lines()
                .any(|l| l.contains(&format!("pid {pid}(caffeinate)"))
                    && l.contains("PreventUserIdleSystemSleep")),
            "{text}"
        );

        drop(awake);
        assert!(!alive(pid), "released on drop");
    }
}
