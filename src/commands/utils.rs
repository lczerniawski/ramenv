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
