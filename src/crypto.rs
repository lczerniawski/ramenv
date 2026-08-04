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

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect()
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
