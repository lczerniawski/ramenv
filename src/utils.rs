use crate::crypto;
use anyhow::Result;

pub fn mask_secret(secret: &str) -> String {
    let characters: Vec<char> = secret.chars().collect();
    let len = characters.len();

    if len <= 4 {
        return "••••".to_string();
    }

    if len <= 10 {
        return format!("{}••••{}", characters[0], characters[len - 1]);
    }

    format!(
        "{}••••{}",
        characters[..4].iter().collect::<String>(),
        characters[len - 4..].iter().collect::<String>()
    )
}

pub trait StringExt {
    fn is_secret(&self) -> bool;
}

impl StringExt for str {
    fn is_secret(&self) -> bool {
        self.trim().starts_with("secret:")
    }
}

pub fn get_plaintext(value: &str, encryption_key: &str) -> Result<String> {
    if value.is_secret() {
        crypto::decrypt_value(value.trim(), encryption_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn mask_secret_handles_each_visibility_boundary() {
        assert_eq!(mask_secret(""), "••••");
        assert_eq!(mask_secret("abcd"), "••••");
        assert_eq!(mask_secret("abcde"), "a••••e");
        assert_eq!(mask_secret("abcdefghij"), "a••••j");
        assert_eq!(mask_secret("abcdefghijk"), "abcd••••hijk");
        assert_eq!(mask_secret("żółw🐢"), "ż••••🐢");
    }

    #[test]
    fn secret_detection_requires_the_exact_prefix_after_whitespace() {
        assert!("secret:abcd".is_secret());
        assert!("  secret:abcd".is_secret());
        assert!(!"secret".is_secret());
        assert!(!"secretary=value".is_secret());
        assert!(!"SECRET:abcd".is_secret());
    }

    #[test]
    fn plaintext_decrypts_only_encrypted_values() {
        let encrypted = crypto::encrypt_value("sensitive", KEY).unwrap();
        assert_eq!(get_plaintext(&encrypted, KEY).unwrap(), "sensitive");
        assert_eq!(
            get_plaintext(&format!("  {encrypted}  "), KEY).unwrap(),
            "sensitive"
        );
        assert_eq!(
            get_plaintext("secretary=value", KEY).unwrap(),
            "secretary=value"
        );
        assert_eq!(get_plaintext("plain", "not-a-key").unwrap(), "plain");
    }

    #[test]
    fn display_value_obeys_reveal_flag() {
        assert_eq!(get_display_value("sensitive", true).unwrap(), "sensitive");
        assert_eq!(get_display_value("sensitive", false).unwrap(), "s••••e");
    }

    #[test]
    fn masking_is_safe_for_varied_unicode_lengths() {
        for length in 0..64 {
            let value = "🦀".repeat(length);
            let masked = mask_secret(&value);
            assert!(masked.contains("••••"));
            assert!(!masked.contains('\u{fffd}'));
        }
    }
}
