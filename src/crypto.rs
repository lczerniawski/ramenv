use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use anyhow::{Context, Ok, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn generate_master_key_hex() -> String {
    let key_bytes = Key::<Aes256Gcm>::generate();
    encode_bytes(key_bytes.to_vec())
}

pub fn generate_signature_key_hex() -> String {
    let key_bytes = Key::<Hmac<Sha256>>::generate();
    encode_bytes(key_bytes.to_vec())
}

pub fn encrypt_value(plaintext: &str, key_hex: &str) -> Result<String> {
    let key_bytes = decode_hex(key_hex).context("failed to decode encryption key")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

    let nonce_bytes = Nonce::generate();
    let mut ciphertext_bytes = cipher
        .encrypt(&nonce_bytes, plaintext.as_bytes())
        .context("failed to encrypt data")?;

    let mut final_payload = nonce_bytes.to_vec();
    final_payload.append(&mut ciphertext_bytes);

    Ok(format!("secret:{}", encode_bytes(final_payload)))
}

pub fn decrypt_value(ciphertext: &str, key_hex: &str) -> Result<String> {
    let raw_hex = ciphertext
        .strip_prefix("secret:")
        .context("Missing required 'secret:' prefix")?;
    let key_bytes = decode_hex(key_hex).context("failed to decode decryption key")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let encrypted_bytes = decode_hex(raw_hex).context("failed to decode encrypted data")?;

    if encrypted_bytes.len() < 12 {
        anyhow::bail!("Encrypted data is too short")
    }

    let (nonce_bytes, ciphertext_bytes) = encrypted_bytes.split_at(12);
    let nonce = Nonce::try_from(nonce_bytes).context("failed to decode nonce")?;

    let plaintext_bytes = cipher
        .decrypt(&nonce, ciphertext_bytes)
        .context("failed to decrypt data")?;

    Ok(
        String::from_utf8(plaintext_bytes)
            .context("failed to convert decrypted bytes to string")?,
    )
}

fn encode_bytes(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(hex_str: &str) -> Result<Vec<u8>> {
    if !hex_str.len().is_multiple_of(2) {
        anyhow::bail!("hex input must contain an even number of characters");
    }

    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

pub fn generate_signature(value: &str, key_hex: &str) -> Result<String> {
    let key_bytes = decode_hex(key_hex).context("failed to decode signature key")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).context("failed to create HMAC")?;

    mac.update(value.as_bytes());
    let signature_bytes = mac.finalize().into_bytes();

    Ok(encode_bytes(signature_bytes.to_vec()))
}

pub fn verify_signature(value: &str, signature_hex: &str, key_hex: &str) -> Result<()> {
    let key_bytes = decode_hex(key_hex).context("failed to decode signature key")?;
    let expected_signature_bytes =
        decode_hex(signature_hex).context("failed to decode signatrue")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).context("failed to create HMAC")?;

    mac.update(value.as_bytes());
    mac.verify_slice(&expected_signature_bytes)
        .context("failed to verify signature")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const OTHER_KEY: &str = "f00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn generated_keys_have_expected_lengths_and_lowercase_hex() {
        for (key, expected_len) in [
            (generate_master_key_hex(), 64),
            (generate_signature_key_hex(), 128),
        ] {
            assert_eq!(key.len(), expected_len);
            assert!(key.chars().all(|character| character.is_ascii_hexdigit()));
            assert_eq!(key, key.to_ascii_lowercase());
        }
    }

    #[test]
    fn encryption_round_trips_empty_unicode_and_multiline_values() {
        for plaintext in ["", "zażółć 🍜", "first\nsecond\n"] {
            let encrypted = encrypt_value(plaintext, KEY).expect("encrypt value");
            assert!(encrypted.starts_with("secret:"));
            assert_eq!(decrypt_value(&encrypted, KEY).unwrap(), plaintext);
        }
    }

    #[test]
    fn encryption_uses_a_fresh_nonce() {
        let first = encrypt_value("same plaintext", KEY).unwrap();
        let second = encrypt_value("same plaintext", KEY).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn decryption_rejects_bad_inputs_without_panicking() {
        for ciphertext in ["plain", "secret:0", "secret:zz", "secret:0011"] {
            assert!(
                decrypt_value(ciphertext, KEY).is_err(),
                "accepted {ciphertext}"
            );
        }
        assert!(decrypt_value(&encrypt_value("value", KEY).unwrap(), OTHER_KEY).is_err());
        assert!(decrypt_value("secret:00112233445566778899aabb00", KEY).is_err());
    }

    #[test]
    fn encryption_rejects_invalid_key_material() {
        for key in ["", "0", "zz", "0011"] {
            assert!(encrypt_value("value", key).is_err(), "accepted key {key}");
        }
    }

    #[test]
    fn signatures_are_deterministic_and_verify() {
        let first = generate_signature("payload", KEY).unwrap();
        let second = generate_signature("payload", KEY).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        verify_signature("payload", &first, KEY).unwrap();
    }

    #[test]
    fn signature_verification_rejects_tampering_and_malformed_hex() {
        let signature = generate_signature("payload", KEY).unwrap();
        assert!(verify_signature("changed", &signature, KEY).is_err());
        assert!(verify_signature("payload", &signature, OTHER_KEY).is_err());
        assert!(verify_signature("payload", "0", KEY).is_err());
        assert!(verify_signature("payload", "zz", KEY).is_err());
    }

    #[test]
    fn arbitrary_malformed_hex_never_panics() {
        for length in 1..128 {
            let odd_or_invalid = if length % 2 == 1 {
                "a".repeat(length)
            } else {
                format!("{}z", "a".repeat(length - 1))
            };
            assert!(decrypt_value(&format!("secret:{odd_or_invalid}"), KEY).is_err());
            assert!(verify_signature("value", &odd_or_invalid, KEY).is_err());
        }
    }

    #[test]
    fn varied_payload_sizes_round_trip() {
        for size in [0, 1, 11, 12, 15, 16, 17, 255, 1024, 16_384] {
            let plaintext = "x".repeat(size);
            let encrypted = encrypt_value(&plaintext, KEY).unwrap();
            assert_eq!(decrypt_value(&encrypted, KEY).unwrap(), plaintext);
        }
    }
}
