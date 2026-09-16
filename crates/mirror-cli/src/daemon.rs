use anyhow::Error;
use mirror_core::sync::SyncOutcome;

#[derive(Default)]
pub struct DaemonStatus {
    last_sync: Option<std::time::SystemTime>,
    last_outcome: Option<SyncOutcome>,
    last_error: Option<String>,
}

impl DaemonStatus {
    pub fn record(&mut self, result: &Result<SyncOutcome, Error>) {
        self.last_sync = Some(std::time::SystemTime::now());

        match result {
            Ok(o) => {
                self.last_outcome = Some(*o);
                self.last_error = None;
            }
            Err(e) => self.last_error = Some(format!("{e:#}")),
        }
    }

    pub fn render(&self) -> String {
        match &self.last_error {
            Some(e) => format!("error: {e}\n"),
            None => match self.last_outcome {
                Some(o) => format!(
                    "ok: {} up, {} down, {} conflict\n",
                    o.uploads, o.downloads, o.conflicts
                ),
                None => "starting up\n".into(),
            },
        }
    }
}
