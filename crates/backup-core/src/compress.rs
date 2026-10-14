//! Per-blob compression, applied before sealing.

use crate::error::{Error, Result};

/// Compression must save at least this fraction of a blob's size to be kept.
///
/// Backups are full of already-compressed data (photos, video, archives) where zstd
/// spends CPU to produce output no smaller. Storing those verbatim also lets restore
/// skip decompression.
const MIN_GAIN: f64 = 0.05;

const ZSTD_LEVEL: i32 = zstd::DEFAULT_COMPRESSION_LEVEL;

/// How a blob's plaintext was stored. The byte values are part of the pack format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None = 0,
    Zstd = 1,
}

impl Compression {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::None),
            1 => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Applies `want`, falling back to `None` when it doesn't pay off. Returns the bytes
/// to store and the algorithm actually used.
pub fn compress(plaintext: &[u8], want: Compression) -> Result<(Vec<u8>, Compression)> {
    if want == Compression::None || plaintext.is_empty() {
        return Ok((plaintext.to_vec(), Compression::None));
    }

    let compressed = zstd::bulk::compress(plaintext, ZSTD_LEVEL)?;
    if compressed.len() as f64 > plaintext.len() as f64 * (1.0 - MIN_GAIN) {
        return Ok((plaintext.to_vec(), Compression::None));
    }
    Ok((compressed, Compression::Zstd))
}

/// Reverses `compress`. `plain_len` comes from the pack header and caps the output,
/// so a corrupt or hostile blob can't expand without bound.
pub fn decompress(stored: Vec<u8>, used: Compression, plain_len: usize) -> Result<Vec<u8>> {
    let out = match used {
        Compression::None => stored,
        Compression::Zstd => zstd::bulk::decompress(&stored, plain_len)
            .map_err(|e| Error::Format(format!("compressed blob: {e}")))?,
    };

    if out.len() != plain_len {
        return Err(Error::Format(format!(
            "blob: {} bytes after decompression, but the header says {plain_len}",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn compressible_data_round_trips_through_zstd() {
        let plaintext = b"abcdefgh".repeat(10_000);
        let (stored, used) = compress(&plaintext, Compression::Zstd).unwrap();
        assert_eq!(used, Compression::Zstd);
        assert!(stored.len() < plaintext.len() / 10);
        assert_eq!(
            decompress(stored, used, plaintext.len()).unwrap(),
            plaintext
        );
    }

    #[test]
    fn compression_is_skipped_when_it_does_not_help() {
        let mut plaintext = vec![0u8; 100_000];
        rand::rng().fill(&mut plaintext[..]);
        let (stored, used) = compress(&plaintext, Compression::Zstd).unwrap();
        assert_eq!(used, Compression::None);
        assert_eq!(stored, plaintext);
    }

    #[test]
    fn compression_disabled_and_empty_input_store_verbatim() {
        let plaintext = b"a".repeat(1000);
        assert_eq!(
            compress(&plaintext, Compression::None).unwrap(),
            (plaintext, Compression::None)
        );
        assert_eq!(
            compress(b"", Compression::Zstd).unwrap(),
            (vec![], Compression::None)
        );
    }

    #[test]
    fn decompress_enforces_the_declared_length() {
        let plaintext = b"xyz".repeat(1000);
        let (stored, used) = compress(&plaintext, Compression::Zstd).unwrap();
        assert!(decompress(stored.clone(), used, plaintext.len() - 1).is_err());
        assert!(decompress(stored, used, plaintext.len() + 1).is_err());
        assert!(decompress(b"abc".to_vec(), Compression::None, 4).is_err());
        assert!(decompress(b"not zstd".to_vec(), Compression::Zstd, 8).is_err());
    }

    #[test]
    fn compression_bytes_round_trip() {
        for c in [Compression::None, Compression::Zstd] {
            assert_eq!(Compression::from_byte(c as u8), Some(c));
        }
        assert_eq!(Compression::from_byte(2), None);
    }
}
