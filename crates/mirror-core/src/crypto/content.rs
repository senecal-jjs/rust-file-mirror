use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use crate::Error;
use crate::error::Result;

// 64 KB cleartext buffer size is an industry-standard best practice
const CHUNK_SIZE: usize = 65536;
// XChaCha20-Poly1305's authentication tag — STREAM appends one per frame, so a
// ciphertext frame is always this many bytes bigger than the plaintext that
// produced it. Reading ciphertext back requires a buffer sized for that.
const TAG_SIZE: usize = 16;

/// A ciphertext part from `StreamingEncryptor::encrypt_next_part`, paired with
/// how many plaintext bytes actually produced it — ciphertext is always larger
/// (a nonce on the first part, a Poly1305 tag per STREAM frame), so callers
/// reporting progress against the *plaintext* file size need this, not
/// `ciphertext.len()`, to stay in the same units as whatever total they declared.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedPart {
    pub ciphertext: Vec<u8>,
    pub plaintext_len: usize,
}

pub struct StreamingEncryptor {
    encryptor: Option<EncryptorBE32<XChaCha20Poly1305>>,
    buf_reader: BufReader<File>,
    input_path: PathBuf,
    aad: String,
    nonce: [u8; 19],
}

impl StreamingEncryptor {
    pub fn new(
        key: &SecretBox<[u8; 32]>,
        input_path: &Path,
        aad: &str,
        nonce: Option<[u8; 19]>,
    ) -> Result<StreamingEncryptor> {
        // STREAM's BE32 construction reserves 5 of XChaCha20's 24 nonce bytes for its own
        // per-chunk counter + last-block flag — the caller only supplies the remaining 19.
        let mut nonce_bytes = [0u8; 19];

        if let Some(n) = nonce {
            nonce_bytes = n
        } else {
            rand::rng().fill(&mut nonce_bytes);
        }

        let nonce: aead_stream::Nonce<
            XChaCha20Poly1305,
            aead_stream::StreamBE32<XChaCha20Poly1305>,
        > = nonce_bytes.into();

        // Initialize the streaming AEAD encryptor
        let aead = XChaCha20Poly1305::new(key.expose_secret().into());
        let encryptor = EncryptorBE32::from_aead(aead, &nonce);

        let input = File::open(input_path).map_err(|source| Error::Io {
            path: input_path.to_path_buf(),
            source,
        })?;

        let buf_reader = BufReader::new(input);

        Ok(StreamingEncryptor {
            encryptor: Some(encryptor),
            buf_reader,
            input_path: input_path.to_path_buf(),
            aad: aad.to_string(),
            nonce: nonce_bytes,
        })
    }

    pub fn get_nonce(&self) -> [u8; 19] {
        self.nonce
    }

    pub fn encrypt_next_part(&mut self, part_size_bytes: usize) -> Result<Option<EncryptedPart>> {
        // `self.encryptor` only ever becomes `None` once the terminal frame has
        // actually been produced (below) — that, not a zero-byte read, is the real
        // "nothing left" signal. Relying on `bytes_read == 0` for that would treat
        // a genuinely empty file's very first read the same as a truly exhausted
        // reader, and skip ever emitting (and authenticating) its terminal frame.
        if self.encryptor.is_none() {
            return Ok(None);
        }

        let mut ciphertext: Vec<u8> = Vec::new();
        let mut plaintext_len: usize = 0;

        loop {
            // A single `.read()` call is never guaranteed to fill the buffer, even with
            // plenty of data left — `take(N).read_to_end()` loops until it genuinely has
            // N bytes or hits true EOF, which a bare `.read()` does not.
            let mut chunk_vec = Vec::with_capacity(CHUNK_SIZE);
            let bytes_read = (&mut self.buf_reader)
                .take(CHUNK_SIZE as u64)
                .read_to_end(&mut chunk_vec)
                .map_err(|source| Error::Io {
                    path: self.input_path.clone(),
                    source,
                })?;

            plaintext_len += bytes_read;

            // Either this read came back empty (true EOF, possibly on the very first
            // attempt for an empty file) or peeking ahead shows nothing further —
            // either way, `chunk_vec` (however small, even empty) is the terminal frame.
            let is_last = bytes_read == 0
                || self
                    .buf_reader
                    .fill_buf()
                    .map_err(|source| Error::Io {
                        path: self.input_path.clone(),
                        source,
                    })?
                    .is_empty();

            if is_last {
                // encrypt_last_in_place takes `self` by value — it consumes the encryptor,
                // so this must be the terminal action of the loop.
                if let Some(encryptor) = self.encryptor.take() {
                    encryptor
                        .encrypt_last_in_place(self.aad.as_bytes(), &mut chunk_vec)
                        .map_err(|source| Error::Crypto(format!("{}", source)))?;

                    ciphertext.append(&mut chunk_vec);
                }

                break;
            }

            let Some(encryptor) = self.encryptor.as_mut() else {
                return Ok(None);
            };

            encryptor
                .encrypt_next_in_place(self.aad.as_bytes(), &mut chunk_vec)
                .map_err(|source| Error::Crypto(format!("{}", source)))?;

            ciphertext.append(&mut chunk_vec);

            if ciphertext.len() >= part_size_bytes {
                break;
            }
        }

        Ok(Some(EncryptedPart {
            ciphertext,
            plaintext_len,
        }))
    }
}

/// Unlike `StreamingEncryptor`, this doesn't read from a local file — real
/// ciphertext arrives as a stream of network reads (an S3 download), of whatever
/// size the transport happens to hand over. `feed` buffers those internally and
/// only decrypts once a full STREAM frame (`CHUNK_SIZE + TAG_SIZE` bytes) has
/// accumulated, so callers never have to reconstruct frame alignment themselves.
pub struct StreamingDecryptor {
    decryptor: DecryptorBE32<XChaCha20Poly1305>,
    aad: String,
    buffer: Vec<u8>,
}

impl StreamingDecryptor {
    pub fn new(
        key: &SecretBox<[u8; 32]>,
        nonce_bytes: [u8; 19],
        aad: &str,
    ) -> Result<StreamingDecryptor> {
        let nonce: aead_stream::Nonce<
            XChaCha20Poly1305,
            aead_stream::StreamBE32<XChaCha20Poly1305>,
        > = nonce_bytes.into();

        let aead = XChaCha20Poly1305::new(key.expose_secret().into());
        let decryptor = DecryptorBE32::from_aead(aead, &nonce);

        Ok(StreamingDecryptor {
            decryptor,
            aad: aad.to_string(),
            buffer: Vec::new(),
        })
    }

    /// Feed newly-arrived ciphertext bytes, in whatever size they happen to show
    /// up. Decrypts any frame that's now fully buffered and returns the resulting
    /// plaintext — often empty, if not enough has arrived yet to complete one.
    ///
    /// Deliberately never drains the buffer down to empty: STREAM's last frame
    /// must go through `decrypt_last_in_place`, not `decrypt_next_in_place`, even
    /// when it happens to be a full-size frame — so at least one frame's worth is
    /// always held back for `finish`, since only the caller knows when the
    /// transfer is actually done.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(bytes);

        let mut plaintext = Vec::new();

        while self.buffer.len() > CHUNK_SIZE + TAG_SIZE {
            let mut frame: Vec<u8> = self.buffer.drain(..CHUNK_SIZE + TAG_SIZE).collect();

            self.decryptor
                .decrypt_next_in_place(self.aad.as_bytes(), &mut frame)
                .map_err(|source| {
                    let backtrace = std::backtrace::Backtrace::capture();
                    Error::Crypto(format!("{source}\n{backtrace}"))
                })?;

            plaintext.append(&mut frame);
        }

        Ok(plaintext)
    }

    /// Call once, after the very last byte has been fed — decrypts and
    /// authenticates whatever's left buffered. Consumes the decryptor since STREAM's
    /// finalizing call is terminal by construction.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        let mut frame = std::mem::take(&mut self.buffer);

        self.decryptor
            .decrypt_last_in_place(self.aad.as_bytes(), &mut frame)
            .map_err(|source| {
                let backtrace = std::backtrace::Backtrace::capture();
                Error::Crypto(format!("{source}\n{backtrace}"))
            })?;

        Ok(frame)
    }
}

/// stream cipher encryption, from plaintext [input_path] to ciphertext [output_path]
pub fn encrypt(
    key: &SecretBox<[u8; 32]>,
    input_path: &Path,
    output_path: &Path,
    associated_data: &str,
) -> Result<()> {
    let input = File::open(input_path).map_err(|source| Error::Io {
        path: input_path.to_path_buf(),
        source,
    })?;

    let mut output = File::create(output_path).map_err(|source| Error::Io {
        path: output_path.to_path_buf(),
        source,
    })?;

    // STREAM's BE32 construction reserves 5 of XChaCha20's 24 nonce bytes for its own
    // per-chunk counter + last-block flag — the caller only supplies the remaining 19.
    let mut nonce_bytes = [0u8; 19];
    rand::rng().fill(&mut nonce_bytes);

    let nonce: aead_stream::Nonce<XChaCha20Poly1305, aead_stream::StreamBE32<XChaCha20Poly1305>> =
        nonce_bytes.into();

    // 2. Write the raw nonce directly to the beginning of the encrypted file
    output.write_all(&nonce).map_err(|source| Error::Io {
        path: output_path.to_path_buf(),
        source,
    })?;

    // 3. Initialize the streaming AEAD encryptor
    let aead = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut encryptor = EncryptorBE32::from_aead(aead, &nonce);

    let mut buf_reader = BufReader::new(input);

    loop {
        // A single `.read()` call is never guaranteed to fill the buffer, even with
        // plenty of data left — `take(N).read_to_end()` loops until it genuinely has
        // N bytes or hits true EOF, which a bare `.read()` does not.
        let mut chunk_vec = Vec::with_capacity(CHUNK_SIZE);
        let bytes_read = (&mut buf_reader)
            .take(CHUNK_SIZE as u64)
            .read_to_end(&mut chunk_vec)
            .map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?;

        if bytes_read == 0 {
            break; // end of file
        }

        // Peek ahead without consuming — an empty result means this chunk is the last one.
        let is_last = buf_reader
            .fill_buf()
            .map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?
            .is_empty();

        if is_last {
            // encrypt_last_in_place takes `self` by value — it consumes the encryptor,
            // so this must be the terminal action of the loop.
            encryptor
                .encrypt_last_in_place(associated_data.as_bytes(), &mut chunk_vec)
                .map_err(|source| Error::Crypto(format!("{}", source)))?;

            output.write_all(&chunk_vec).map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?;

            break;
        }

        encryptor
            .encrypt_next_in_place(associated_data.as_bytes(), &mut chunk_vec)
            .map_err(|source| Error::Crypto(format!("{}", source)))?;

        output.write_all(&chunk_vec).map_err(|source| Error::Io {
            path: input_path.to_path_buf(),
            source,
        })?;
    }

    Ok(())
}

pub fn decrypt(
    key: &SecretBox<[u8; 32]>,
    input_path: &Path,
    output_path: &Path,
    associated_data: &str,
) -> Result<()> {
    let mut input = File::open(input_path).map_err(|source| Error::Io {
        path: input_path.to_path_buf(),
        source,
    })?;

    let mut output = File::create(output_path).map_err(|source| Error::Io {
        path: output_path.to_path_buf(),
        source,
    })?;

    // Read back the 19-byte nonce prefix `encrypt` wrote at the start of the file —
    // decryption must use the exact same nonce encryption did, never a new one.
    let mut nonce_bytes = [0u8; 19];
    input
        .read_exact(&mut nonce_bytes)
        .map_err(|source| Error::Io {
            path: input_path.to_path_buf(),
            source,
        })?;

    let nonce: aead_stream::Nonce<XChaCha20Poly1305, aead_stream::StreamBE32<XChaCha20Poly1305>> =
        nonce_bytes.into();

    // 3. Initialize the streaming AEAD encryptor
    let aead = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut decryptor = DecryptorBE32::from_aead(aead, &nonce);

    let mut buf_reader = BufReader::new(input);

    loop {
        // Ciphertext frames are CHUNK_SIZE + TAG_SIZE bytes (the tag STREAM appends to
        // each frame), and a single `.read()` call is never guaranteed to fill a buffer
        // even with plenty of data left — `take(N).read_to_end()` loops until it
        // genuinely has one whole frame or hits true EOF.
        let mut chunk_vec = Vec::with_capacity(CHUNK_SIZE + TAG_SIZE);
        let bytes_read = (&mut buf_reader)
            .take((CHUNK_SIZE + TAG_SIZE) as u64)
            .read_to_end(&mut chunk_vec)
            .map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?;

        if bytes_read == 0 {
            break; // end of file
        }

        // Peek ahead without consuming — an empty result means this chunk is the last one.
        let is_last = buf_reader
            .fill_buf()
            .map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?
            .is_empty();

        if is_last {
            // decrypt_last_in_place takes `self` by value — it consumes the decryptor,
            // so this must be the terminal action of the loop.
            decryptor
                .decrypt_last_in_place(associated_data.as_bytes(), &mut chunk_vec)
                .map_err(|source| {
                    let backtrace = std::backtrace::Backtrace::capture();
                    Error::Crypto(format!("{source}\n{backtrace}"))
                })?;

            output.write_all(&chunk_vec).map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?;

            break;
        }

        decryptor
            .decrypt_next_in_place(associated_data.as_bytes(), &mut chunk_vec)
            .map_err(|source| {
                let backtrace = std::backtrace::Backtrace::capture();
                Error::Crypto(format!("{source}\n{backtrace}"))
            })?;

        output.write_all(&chunk_vec).map_err(|source| Error::Io {
            path: input_path.to_path_buf(),
            source,
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let mut plain_file = NamedTempFile::new().unwrap();
        write!(plain_file, "Hello World").unwrap();
        let plain_file_ref: &Path = plain_file.path();

        let cipher_file = NamedTempFile::new().unwrap();
        let cipher_file_ref: &Path = cipher_file.path();

        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);

        let key = SecretBox::new(Box::new(key_bytes));

        encrypt(&key, plain_file_ref, cipher_file_ref, "fmt/tmp1.txt").unwrap();

        let decrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file_ref = decrypted_file.path();

        decrypt(&key, cipher_file_ref, decrypted_file_ref, "fmt/tmp1.txt").unwrap();

        let plaintext = fs::read_to_string(decrypted_file.path()).unwrap();

        assert_eq!("Hello World", plaintext);
    }

    /// A single `Read::read()` call is never guaranteed to fill its buffer, even with
    /// plenty of data left — this regression-tests a file spanning several STREAM
    /// frames (not just the single final frame every other test here exercises).
    #[test]
    fn round_trip_encrypt_decrypt_spans_multiple_frames() {
        let mut plain_file = NamedTempFile::new().unwrap();
        let mut content = vec![0u8; CHUNK_SIZE * 3 + 12345];
        rand::rng().fill(content.as_mut_slice());
        plain_file.write_all(&content).unwrap();
        let plain_file_ref: &Path = plain_file.path();

        let cipher_file = NamedTempFile::new().unwrap();
        let cipher_file_ref: &Path = cipher_file.path();

        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let key = SecretBox::new(Box::new(key_bytes));

        encrypt(&key, plain_file_ref, cipher_file_ref, "multi-frame").unwrap();

        let decrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file_ref = decrypted_file.path();

        decrypt(&key, cipher_file_ref, decrypted_file_ref, "multi-frame").unwrap();

        let result = fs::read(decrypted_file_ref).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn streaming_encryptor_and_decryptor_round_trip_across_many_parts() {
        let mut plain_file = NamedTempFile::new().unwrap();
        // Several STREAM frames (CHUNK_SIZE each) *and* several parts (part size
        // smaller than one frame), so both boundaries get exercised at once.
        let mut content = vec![0u8; CHUNK_SIZE * 3 + 12345];
        rand::rng().fill(content.as_mut_slice());
        plain_file.write_all(&content).unwrap();
        let plain_file_ref: &Path = plain_file.path();

        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let key = SecretBox::new(Box::new(key_bytes));

        let mut encryptor =
            StreamingEncryptor::new(&key, plain_file_ref, "streaming", None).unwrap();
        let nonce = encryptor.get_nonce();

        let mut decryptor = StreamingDecryptor::new(&key, nonce, "streaming").unwrap();

        let mut result = Vec::new();

        // Parts arrive from encrypt_next_part at a size unrelated to CHUNK_SIZE +
        // TAG_SIZE (the decryptor's internal frame size) — feed() has to buffer and
        // realign them on its own, the same way it would with arbitrarily-sized
        // reads off a real network download.
        let part_size = CHUNK_SIZE / 3;
        while let Some(part) = encryptor.encrypt_next_part(part_size).unwrap() {
            result.extend(decryptor.feed(&part.ciphertext).unwrap());
        }

        result.extend(decryptor.finish().unwrap());

        assert_eq!(result, content);
    }

    #[test]
    fn streaming_decryptor_finish_handles_an_exact_full_final_frame() {
        // Plaintext is an exact multiple of CHUNK_SIZE, so the true final frame is
        // itself a full CHUNK_SIZE + TAG_SIZE ciphertext frame — the edge case that
        // would trip up an off-by-one in feed()'s greedy-drain condition (it must
        // never mistake the last full frame for just another "next" one).
        let mut plain_file = NamedTempFile::new().unwrap();
        let mut content = vec![0u8; CHUNK_SIZE * 2];
        rand::rng().fill(content.as_mut_slice());
        plain_file.write_all(&content).unwrap();
        let plain_file_ref: &Path = plain_file.path();

        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let key = SecretBox::new(Box::new(key_bytes));

        let mut encryptor = StreamingEncryptor::new(&key, plain_file_ref, "exact", None).unwrap();
        let nonce = encryptor.get_nonce();

        let mut ciphertext = Vec::new();
        while let Some(part) = encryptor.encrypt_next_part(CHUNK_SIZE + TAG_SIZE).unwrap() {
            ciphertext.extend(part.ciphertext);
        }

        let mut decryptor = StreamingDecryptor::new(&key, nonce, "exact").unwrap();
        let mut result = decryptor.feed(&ciphertext).unwrap();
        result.extend(decryptor.finish().unwrap());

        assert_eq!(result, content);
    }

    #[test]
    fn streaming_encryptor_produces_an_authenticated_terminal_frame_for_an_empty_file() {
        // An empty file's first read comes back 0 bytes on the very first attempt —
        // indistinguishable, without the encryptor.is_none() check, from a reader
        // that's already been fully consumed by a prior call. Left unhandled, that
        // meant encrypt_next_part returned None without ever calling
        // encrypt_last_in_place, silently skipping authentication entirely for a
        // 0-byte file instead of emitting the tag-only terminal frame it still owes.
        let plain_file = NamedTempFile::new().unwrap();
        let plain_file_ref: &Path = plain_file.path();

        let mut key_bytes = [0u8; 32];
        rand::rng().fill(&mut key_bytes);
        let key = SecretBox::new(Box::new(key_bytes));

        let mut encryptor = StreamingEncryptor::new(&key, plain_file_ref, "empty", None).unwrap();
        let nonce = encryptor.get_nonce();

        // A real terminal frame: just the Poly1305 tag, no plaintext bytes behind it —
        // not the empty `Vec` the bug used to (silently, un-authenticated) return.
        let part = encryptor.encrypt_next_part(0).unwrap();
        assert_eq!(part.as_ref().map(|p| p.ciphertext.len()), Some(TAG_SIZE));
        assert_eq!(part.as_ref().unwrap().plaintext_len, 0);

        // The terminal frame has already been produced — nothing more to give.
        assert_eq!(encryptor.encrypt_next_part(0).unwrap(), None);

        // And it's genuinely authenticated: StreamingDecryptor can verify it and
        // recovers an empty plaintext, not just "some bytes happened to be returned".
        let mut decryptor = StreamingDecryptor::new(&key, nonce, "empty").unwrap();
        let mut result = decryptor.feed(&part.unwrap().ciphertext).unwrap();
        result.extend(decryptor.finish().unwrap());

        assert!(result.is_empty());
    }
}
