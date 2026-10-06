//! Per-path residency policy: whether a file's bytes should be kept on this device,
//! kept only remotely, or left to the device's own (manual or automatic) choice.

use std::fmt;
use std::str::FromStr;

use globset::{Glob, GlobMatcher};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Always hydrated; never evicted.
    Local,
    /// Evicted once safely synced; new remote files arrive as placeholders.
    OnlineOnly,
    /// Residency is left as-is; eligible for automatic eviction.
    Auto,
}

impl Mode {
    pub fn to_db(self) -> i64 {
        match self {
            Self::Local => 0,
            Self::OnlineOnly => 1,
            Self::Auto => 2,
        }
    }

    pub fn from_db(value: i64) -> Result<Self> {
        match value {
            0 => Ok(Self::Local),
            1 => Ok(Self::OnlineOnly),
            2 => Ok(Self::Auto),
            other => Err(Error::State(format!("unknown pin mode {other}"))),
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Local => "local",
            Self::OnlineOnly => "online-only",
            Self::Auto => "auto",
        })
    }
}

impl FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "local" => Ok(Self::Local),
            "online-only" => Ok(Self::OnlineOnly),
            "auto" => Ok(Self::Auto),
            other => Err(Error::Config(format!(
                "unknown residency {other:?} (expected local, online-only or auto)"
            ))),
        }
    }
}

struct Rule {
    pattern: String,
    matcher: GlobMatcher,
    mode: Mode,
}

impl Rule {
    fn new(pattern: &str, mode: Mode) -> Result<Self> {
        let matcher = Glob::new(pattern)
            .map_err(|e| Error::Config(format!("invalid glob {pattern:?}: {e}")))?
            .compile_matcher();

        Ok(Self {
            pattern: pattern.to_string(),
            matcher,
            mode,
        })
    }
}

/// Resolved residency rules. Precedence: CLI pins (longest matching pattern wins),
/// then config globs (`local` before `online_only`), then `Auto`.
#[derive(Default)]
pub struct Policy {
    pins: Vec<Rule>,
    config: Vec<Rule>,
    default_online_only: bool,
}

impl Policy {
    pub fn new(
        pins: &[(String, Mode)],
        local_globs: &[String],
        online_only_globs: &[String],
        default_online_only: bool,
    ) -> Result<Self> {
        let pins = pins
            .iter()
            .map(|(pattern, mode)| Rule::new(pattern, *mode))
            .collect::<Result<Vec<_>>>()?;

        let config = local_globs
            .iter()
            .map(|p| Rule::new(p, Mode::Local))
            .chain(
                online_only_globs
                    .iter()
                    .map(|p| Rule::new(p, Mode::OnlineOnly)),
            )
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            pins,
            config,
            default_online_only,
        })
    }

    pub fn mode(&self, path: &str) -> Mode {
        let pinned = self
            .pins
            .iter()
            .filter(|rule| rule.matcher.is_match(path))
            .max_by_key(|rule| rule.pattern.len());

        if let Some(rule) = pinned {
            return rule.mode;
        }

        self.config
            .iter()
            .find(|rule| rule.matcher.is_match(path))
            .map_or(Mode::Auto, |rule| rule.mode)
    }

    /// Whether a file this device has never had should arrive as a placeholder.
    pub fn arrives_online_only(&self, path: &str) -> bool {
        match self.mode(path) {
            Mode::Local => false,
            Mode::OnlineOnly => true,
            Mode::Auto => self.default_online_only,
        }
    }
}

/// The candidates each pattern selects: an exact path, a directory prefix, or a glob.
pub fn select<'a>(
    patterns: &[String],
    candidates: impl IntoIterator<Item = &'a str>,
) -> Result<std::collections::BTreeSet<String>> {
    let rules = patterns
        .iter()
        .map(|p| {
            let dir = format!("{}/", p.trim_end_matches('/'));
            Rule::new(p, Mode::Auto).map(|rule| (p.as_str(), dir, rule.matcher))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(candidates
        .into_iter()
        .filter(|path| {
            rules.iter().any(|(exact, dir, matcher)| {
                path == exact || path.starts_with(dir.as_str()) || matcher.is_match(path)
            })
        })
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_beat_config_and_longest_pin_wins() {
        let policy = Policy::new(
            &[
                ("Archive/**".to_string(), Mode::OnlineOnly),
                ("Archive/keep/**".to_string(), Mode::Local),
            ],
            &["**/*.md".to_string()],
            &["**/*.iso".to_string()],
            false,
        )
        .unwrap();

        assert_eq!(policy.mode("Archive/old.bin"), Mode::OnlineOnly);
        assert_eq!(policy.mode("Archive/keep/a.bin"), Mode::Local);
        assert_eq!(policy.mode("Archive/notes.md"), Mode::OnlineOnly);
        assert_eq!(policy.mode("notes.md"), Mode::Local);
        assert_eq!(policy.mode("disk.iso"), Mode::OnlineOnly);
        assert_eq!(policy.mode("other.txt"), Mode::Auto);
    }

    #[test]
    fn default_residency_only_affects_auto_paths() {
        let policy = Policy::new(&[], &["keep/**".to_string()], &[], true).unwrap();

        assert!(policy.arrives_online_only("a.txt"));
        assert!(!policy.arrives_online_only("keep/a.txt"));
    }

    #[test]
    fn select_matches_exact_paths_directories_and_globs() {
        let candidates = [
            "a.txt",
            "docs/b.md",
            "docs/sub/c.md",
            "docsish.txt",
            "x.iso",
        ];
        let selected = select(
            &["docs".to_string(), "*.iso".to_string(), "a.txt".to_string()],
            candidates,
        )
        .unwrap();

        assert_eq!(
            selected.into_iter().collect::<Vec<_>>(),
            vec!["a.txt", "docs/b.md", "docs/sub/c.md", "x.iso"]
        );
    }
}
