use crate::crypto;
use anyhow::Result;

pub fn mask_secret(secret: &str) -> String {
    let len = secret.len();

    if len <= 4 {
        return "••••".to_string();
    }

    if len <= 10 {
        return format!("{}••••{}", &secret[..1], &secret[len - 1..]);
    }

    format!("{}••••{}", &secret[..4], &secret[len - 4..])
}

pub trait StringExt {
    fn is_secret(&self) -> bool;
}

impl StringExt for str {
    fn is_secret(&self) -> bool {
        self.trim().starts_with("secret")
    }
}

pub fn get_plaintext(value: &str, encryption_key: &str) -> Result<String> {
    if value.is_secret() {
        crypto::decrypt_value(value, encryption_key)
    } else {
        Ok(value.to_string())
    }
}

pub fn get_display_value(plaintext: &str, reveal_secrets: bool) -> Result<String> {
    if reveal_secrets {
        Ok(plaintext.to_string())
    } else {
        Ok(mask_secret(plaintext))
    }
}
