use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::Error;
use crate::error::Result;

// 64 KB cleartext buffer size is an industry-standard best practice
const CHUNK_SIZE: usize = 65536;
// Each encrypted chunk expands by a 16-byte Poly1305 authentication tag
const TAG_SIZE: usize = 16;
const TOTAL_BUFFER_SIZE: usize = CHUNK_SIZE + TAG_SIZE; // 65552 bytes

/// stream cipher encryption, from plaintext [input_path] to ciphertext [output_path]
pub fn encrypt(
    key: &SecretBox<[u8; 32]>,
    input_path: &Path,
    output_path: &Path,
    store_key: &str,
) -> Result<()> {
    let mut input = File::open(input_path).map_err(|source| Error::Io {
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

    let mut buffer = vec![0u8; TOTAL_BUFFER_SIZE];

    loop {
        let bytes_read = input
            .read(&mut buffer[..CHUNK_SIZE])
            .map_err(|source| Error::Io {
                path: input_path.to_path_buf(),
                source,
            })?;

        if bytes_read == 0 {
            break; // end of file
        }

        // encrypt_next_in_place takes an `aead::Buffer` trait implementation.
        // A mutable vector `&mut Vec<u8>` satisfies this by automatically extending
        // to handle the tag, provided its capacity allows it.
        // We truncate the vector to the length of data read so the cipher knows how much to encrypt.
        let mut chunk_vec = buffer[..bytes_read].to_vec();

        encryptor
            .encrypt_next_in_place(store_key.as_bytes(), &mut chunk_vec)
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
    store_key: &str,
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

    let aead = XChaCha20Poly1305::new(key.expose_secret().into());
    let mut decryptor = DecryptorBE32::from_aead(aead, &nonce);

    let mut buffer = vec![0u8; TOTAL_BUFFER_SIZE];

    loop {
        let bytes_read = input.read(&mut buffer).map_err(|source| Error::Io {
            path: input_path.to_path_buf(),
            source,
        })?;

        if bytes_read == 0 {
            break; // end of file
        }

        let mut chunk_vec = buffer[..bytes_read].to_vec();

        // decrypt next in place verifies the tag, removes it,
        // and mutates chunk_vec back into pure plaintext
        decryptor
            .decrypt_next_in_place(store_key.as_bytes(), &mut chunk_vec)
            .map_err(|source| Error::Crypto(format!("{}", source)))?;

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
}
