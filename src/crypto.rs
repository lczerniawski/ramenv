use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit},
};
use anyhow::Ok;

pub fn generate_master_key_hex() -> String {
    let key_bytes = Key::<Aes256Gcm>::generate();
    encode_bytes(key_bytes.to_vec())
}

pub fn encrypt_value(plaintext: &str, key_hex: &str) -> anyhow::Result<String> {
    let key_bytes = decode_hex(key_hex)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

    let nonce_bytes = Nonce::generate();
    let mut ciphertext_bytes = cipher.encrypt(&nonce_bytes, plaintext.as_bytes())?;

    let mut final_payload = nonce_bytes.to_vec();
    final_payload.append(&mut ciphertext_bytes);

    Ok(encode_bytes(final_payload))
}

pub fn decrypt_value(ciphertext: &str, key_hex: &str) -> anyhow::Result<String> {
    let key_bytes = decode_hex(key_hex)?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
    let encrypted_bytes = decode_hex(ciphertext)?;

    if encrypted_bytes.len() < 12 {
        anyhow::bail!("Encrypted data is too short")
    }

    let (nonce_bytes, ciphertext_bytes) = encrypted_bytes.split_at(12);
    let nonce = Nonce::try_from(nonce_bytes)?;

    let plaintext_bytes = cipher.decrypt(&nonce, ciphertext_bytes)?;

    Ok(String::from_utf8(plaintext_bytes)?)
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
