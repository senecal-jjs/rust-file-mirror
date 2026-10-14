//! Content-defined chunking (FastCDC 2020, normalization level 2).
//!
//! Boundaries depend on the content, not on offsets, so inserting bytes into a file
//! only disturbs the chunks around the edit and everything after it still
//! deduplicates. Boundaries are part of the repository format: the parameters are
//! stored in the repository config, and the golden-vector tests fail if a `fastcdc`
//! upgrade (or anything else) moves them.

use std::io::Read;

use fastcdc::v2020::{self, Normalization, StreamCDC};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DEFAULT_MIN_SIZE: usize = 256 * 1024;
pub const DEFAULT_AVG_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MAX_SIZE: usize = 4 * 1024 * 1024;

const NORMALIZATION: Normalization = Normalization::Level2;
const SEED: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkerConfig {
    pub min_size: usize,
    pub avg_size: usize,
    pub max_size: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        Self {
            min_size: DEFAULT_MIN_SIZE,
            avg_size: DEFAULT_AVG_SIZE,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

impl ChunkerConfig {
    /// `fastcdc` only `debug_assert`s its limits, so a bad config read from a
    /// repository must be caught here rather than silently mis-chunking in release.
    pub fn validate(&self) -> Result<()> {
        let Self {
            min_size,
            avg_size,
            max_size,
        } = *self;
        let check = |ok: bool, msg: String| {
            if ok {
                Ok(())
            } else {
                Err(Error::ChunkerConfig(msg))
            }
        };

        check(
            (v2020::MINIMUM_MIN..=v2020::MINIMUM_MAX).contains(&min_size),
            format!(
                "min_size {min_size} outside {}..={}",
                v2020::MINIMUM_MIN,
                v2020::MINIMUM_MAX
            ),
        )?;
        check(
            (v2020::AVERAGE_MIN..=v2020::AVERAGE_MAX).contains(&avg_size),
            format!(
                "avg_size {avg_size} outside {}..={}",
                v2020::AVERAGE_MIN,
                v2020::AVERAGE_MAX
            ),
        )?;
        check(
            (v2020::MAXIMUM_MIN..=v2020::MAXIMUM_MAX).contains(&max_size),
            format!(
                "max_size {max_size} outside {}..={}",
                v2020::MAXIMUM_MIN,
                v2020::MAXIMUM_MAX
            ),
        )?;
        check(
            avg_size.is_power_of_two(),
            format!("avg_size {avg_size} is not a power of two"),
        )?;
        check(
            min_size.is_multiple_of(2) && max_size.is_multiple_of(2),
            "min_size and max_size must be even".into(),
        )?;
        check(
            min_size < avg_size && avg_size < max_size,
            format!("want min < avg < max, got {min_size} / {avg_size} / {max_size}"),
        )
    }
}

/// Splits `source` into chunks. Read errors end the iteration with that error.
pub fn chunks<R: Read>(
    config: ChunkerConfig,
    source: R,
) -> Result<impl Iterator<Item = Result<Vec<u8>>>> {
    config.validate()?;

    let cdc = StreamCDC::with_level_and_seed(
        source,
        config.min_size,
        config.avg_size,
        config.max_size,
        NORMALIZATION,
        SEED,
    );

    Ok(cdc.map(|chunk| match chunk {
        Ok(chunk) => Ok(chunk.data),
        Err(fastcdc::v2020::Error::IoError(e)) => Err(Error::Io(e)),
        Err(e) => Err(Error::Invalid(format!("chunker: {e}"))),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    const SMALL: ChunkerConfig = ChunkerConfig {
        min_size: 2 * 1024,
        avg_size: 8 * 1024,
        max_size: 32 * 1024,
    };

    /// Deterministic pseudo-random bytes (xorshift64*), independent of any crate's
    /// RNG algorithm, so the golden vectors can never move because of a dependency.
    fn data(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn split(config: ChunkerConfig, input: &[u8]) -> Vec<Vec<u8>> {
        chunks(config, input)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap()
    }

    fn lengths(chunks: &[Vec<u8>]) -> Vec<usize> {
        chunks.iter().map(Vec::len).collect()
    }

    #[test]
    fn round_trip() {
        let input = data(1_000_000, 1);
        assert_eq!(split(SMALL, &input).concat(), input);
    }

    #[test]
    fn empty_input_produces_no_chunks() {
        assert!(split(SMALL, b"").is_empty());
    }

    #[test]
    fn size_bounds() {
        let chunks = split(SMALL, &data(2_000_000, 2));
        let (last, rest) = chunks.split_last().unwrap();
        for chunk in rest {
            assert!(
                (SMALL.min_size..=SMALL.max_size).contains(&chunk.len()),
                "{}",
                chunk.len()
            );
        }
        assert!(last.len() <= SMALL.max_size);
    }

    #[test]
    fn average_size_near_target() {
        let input = data(8_000_000, 3);
        let n = split(SMALL, &input).len();
        let avg = input.len() / n;
        assert!(
            (SMALL.avg_size / 2..=SMALL.avg_size * 2).contains(&avg),
            "average chunk {avg} too far from {}",
            SMALL.avg_size
        );
    }

    #[test]
    fn deterministic() {
        let input = data(500_000, 4);
        assert_eq!(split(SMALL, &input), split(SMALL, &input));
    }

    /// A reader that hands out at most `step` bytes per call.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.step.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn chunking_is_independent_of_read_size() {
        let input = data(300_000, 5);
        let expected = split(SMALL, &input);
        for step in [1, 7, 4096, 100_000] {
            let got: Vec<_> = chunks(SMALL, Trickle { data: &input, step })
                .unwrap()
                .collect::<Result<_>>()
                .unwrap();
            assert_eq!(got, expected, "read size {step}");
        }
    }

    fn shared(a: &[Vec<u8>], b: &[Vec<u8>]) -> usize {
        let a: std::collections::HashSet<_> = a.iter().collect();
        b.iter().filter(|c| a.contains(c)).count()
    }

    #[test]
    fn shift_resistance() {
        let input = data(2_000_000, 6);
        let mut shifted = data(100, 99);
        shifted.extend_from_slice(&input);

        let before = split(SMALL, &input);
        let after = split(SMALL, &shifted);
        // Everything but the first chunk or two re-synchronizes.
        assert!(shared(&before, &after) >= before.len() - 3);
    }

    #[test]
    fn middle_edit_is_localized() {
        let input = data(2_000_000, 7);
        let mut edited = input.clone();
        edited.splice(1_000_000..1_000_000, data(1024, 77));

        let before = split(SMALL, &input);
        let after = split(SMALL, &edited);
        let new_bytes: usize = {
            let old: std::collections::HashSet<_> = before.iter().collect();
            after
                .iter()
                .filter(|c| !old.contains(c))
                .map(Vec::len)
                .sum()
        };
        assert!(
            new_bytes <= 4 * SMALL.max_size,
            "{new_bytes} new bytes for a 1 KiB insert"
        );
    }

    /// Chunk boundaries are part of the repository format. If this fails, the
    /// chunker's output changed and new backups would stop deduplicating against old
    /// ones: don't update the vectors, find out what moved.
    #[test]
    fn golden_boundaries() {
        assert_eq!(lengths(&split(SMALL, &data(200_000, 42))), GOLDEN_SMALL);
        assert_eq!(
            lengths(&split(
                ChunkerConfig::default(),
                &data(12 * 1024 * 1024, 42)
            )),
            GOLDEN_DEFAULT
        );
    }

    const GOLDEN_SMALL: &[usize] = &[
        9056, 3616, 10323, 13657, 10228, 10352, 10053, 8923, 14651, 8393, 8574, 8657, 9283, 10929,
        7329, 8845, 10698, 6518, 9582, 8653, 8471, 3209,
    ];
    const GOLDEN_DEFAULT: &[usize] = &[
        1492424, 2146027, 1693891, 1064564, 1147307, 1689079, 1179577, 1400213, 769830,
    ];

    #[test]
    fn config_validation() {
        assert!(ChunkerConfig::default().validate().is_ok());
        assert!(SMALL.validate().is_ok());

        let bad = [
            ChunkerConfig {
                min_size: 32,
                ..SMALL
            },
            ChunkerConfig {
                avg_size: 10_000,
                ..SMALL
            },
            ChunkerConfig {
                max_size: 64 * 1024 * 1024,
                ..SMALL
            },
            ChunkerConfig {
                min_size: 2049,
                ..SMALL
            },
            ChunkerConfig {
                min_size: 16 * 1024,
                ..SMALL
            },
            ChunkerConfig {
                max_size: 8 * 1024,
                ..SMALL
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "{config:?} accepted");
            assert!(chunks(config, &b""[..]).is_err());
        }
    }

    struct Failing;

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk on fire"))
        }
    }

    #[test]
    fn read_error_fails_fast() {
        let mut iter = chunks(SMALL, Failing).unwrap();
        assert!(matches!(iter.next(), Some(Err(Error::Io(_)))));
    }
}
