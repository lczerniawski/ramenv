use std::net::IpAddr;

use anyhow::Ok;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleType {
    String {
        min_len: Option<usize>,
        max_len: Option<usize>,
    },
    Integer {
        min_value: Option<i64>,
        max_value: Option<i64>,
    },
    Float {
        min_value: Option<f64>,
        max_value: Option<f64>,
    },
    Boolean,
    Port,
    Uri,
    IP,
    Email,
    Regex {
        pattern: String,
    },
}

impl RuleType {
    pub fn validate(&self, key: &str, value: &str, env: &str) -> anyhow::Result<()> {
        match self {
            RuleType::String { min_len, max_len } => {
                let len = value.len();

                if let Some(min) = min_len
                    && len < *min
                {
                    anyhow::bail!("[{}] Key '{}' is too short (min: {})", env, key, min);
                }

                if let Some(max) = max_len
                    && len > *max
                {
                    anyhow::bail!("[{}] Key '{}' is too long (max: {})", env, key, max);
                }
            }
            RuleType::Integer {
                min_value,
                max_value,
            } => {
                let num = value.parse::<i64>().map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{} must be an integer, got: '{}'",
                        env,
                        key,
                        value
                    )
                })?;

                if let Some(min) = min_value
                    && num < *min
                {
                    anyhow::bail!(
                        "[{}] Key '{}' value {} is too small (min: {})",
                        env,
                        key,
                        num,
                        min
                    );
                }

                if let Some(max) = max_value
                    && num > *max
                {
                    anyhow::bail!(
                        "[{}] Key '{}' value {} is too large (max: {})",
                        env,
                        key,
                        num,
                        max
                    );
                }
            }
            RuleType::Float {
                min_value,
                max_value,
            } => {
                let num = value.parse::<f64>().map_err(|_| {
                    anyhow::anyhow!("[{}] Key '{}' must be a float, got: '{}'", env, key, value)
                })?;

                if let Some(min) = min_value
                    && num < *min
                {
                    anyhow::bail!(
                        "[{}] Key '{}' value {} is too small (min: {})",
                        env,
                        key,
                        num,
                        min
                    );
                }

                if let Some(max) = max_value
                    && num > *max
                {
                    anyhow::bail!(
                        "[{}] Key '{}' value {} is too large (max: {})",
                        env,
                        key,
                        num,
                        max
                    );
                }
            }
            RuleType::Boolean => {
                value.parse::<bool>().map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{}' must be a boolean (true/false), got: '{}'",
                        env,
                        key,
                        value
                    )
                })?;
            }
            RuleType::Port => {
                let port = value.parse::<u16>().map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{}' must be a valid port number (0-65535), got: '{}'",
                        env,
                        key,
                        value
                    )
                })?;

                if port == 0 {
                    anyhow::bail!("[{}] Key '{}' port cannot be 0", env, key);
                }
            }
            RuleType::Uri => {
                url::Url::parse(value).map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{}' must be a valid URI/URL, got: '{}'",
                        env,
                        key,
                        value
                    )
                })?;
            }
            RuleType::IP => {
                value.parse::<IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{}' must be a valid IP address, got: '{}'",
                        env,
                        key,
                        value
                    )
                })?;
            }
            RuleType::Email => {
                if !value.contains("@")
                    || value.trim().starts_with("@")
                    || value.trim().ends_with("@")
                {
                    anyhow::bail!(
                        "[{}] Key '{}' must be a valid email address, got: '{}'",
                        env,
                        key,
                        value
                    );
                }
            }
            RuleType::Regex { pattern } => {
                let re = regex::Regex::new(pattern).map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] Key '{}' has an invalid regex pattern: '{}'",
                        env,
                        key,
                        pattern
                    )
                })?;

                if !re.is_match(value) {
                    anyhow::bail!(
                        "[{}] Key '{}' does not match the required pattern, got: '{}'",
                        env,
                        key,
                        value
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidationRule {
    #[serde(flatten)]
    pub rule_type: RuleType,
    #[serde(default = "default_true")]
    pub required: bool,
}

impl ValidationRule {
    pub fn new(rule_type: RuleType, required: bool) -> Self {
        Self {
            rule_type,
            required,
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: &str = "test-env";

    #[test]
    fn test_string_validation_success() {
        let rule = RuleType::String {
            min_len: Some(3),
            max_len: Some(6),
        };
        assert!(rule.validate("KEY", "abcd", ENV).is_ok());
    }

    #[test]
    fn test_string_validation_too_short() {
        let rule = RuleType::String {
            min_len: Some(5),
            max_len: None,
        };
        let err = rule.validate("KEY", "abc", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'KEY' is too short (min: 5)"
        );
    }

    #[test]
    fn test_string_validation_too_long() {
        let rule = RuleType::String {
            min_len: None,
            max_len: Some(3),
        };
        let err = rule.validate("KEY", "abcd", ENV).unwrap_err();
        assert_eq!(err.to_string(), "[test-env] Key 'KEY' is too long (max: 3)");
    }

    #[test]
    fn test_integer_validation_success() {
        let rule = RuleType::Integer {
            min_value: Some(-10),
            max_value: Some(100),
        };
        assert!(rule.validate("PORT", "42", ENV).is_ok());
    }

    #[test]
    fn test_integer_validation_invalid_parse() {
        let rule = RuleType::Integer {
            min_value: None,
            max_value: None,
        };
        let err = rule.validate("PORT", "not_an_int", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'PORT must be an integer, got: 'not_an_int'"
        );
    }

    #[test]
    fn test_integer_validation_too_small() {
        let rule = RuleType::Integer {
            min_value: Some(10),
            max_value: None,
        };
        let err = rule.validate("PORT", "5", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'PORT' value 5 is too small (min: 10)"
        );
    }

    #[test]
    fn test_integer_validation_too_large() {
        let rule = RuleType::Integer {
            min_value: None,
            max_value: Some(50),
        };
        let err = rule.validate("PORT", "55", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'PORT' value 55 is too large (max: 50)"
        );
    }

    #[test]
    fn test_float_validation_success() {
        let rule = RuleType::Float {
            min_value: Some(1.5),
            max_value: Some(5.5),
        };
        assert!(rule.validate("RATE", "3.14", ENV).is_ok());
    }

    #[test]
    fn test_float_validation_invalid_parse() {
        let rule = RuleType::Float {
            min_value: None,
            max_value: None,
        };
        let err = rule.validate("RATE", "abc", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'RATE' must be a float, got: 'abc'"
        );
    }

    #[test]
    fn test_float_validation_too_small() {
        let rule = RuleType::Float {
            min_value: Some(2.0),
            max_value: None,
        };
        let err = rule.validate("RATE", "1.9", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'RATE' value 1.9 is too small (min: 2)"
        );
    }

    #[test]
    fn test_float_validation_too_large() {
        let rule = RuleType::Float {
            min_value: None,
            max_value: Some(10.0),
        };
        let err = rule.validate("RATE", "10.1", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'RATE' value 10.1 is too large (max: 10)"
        );
    }

    #[test]
    fn test_boolean_validation_success() {
        let rule = RuleType::Boolean;
        assert!(rule.validate("DEBUG", "true", ENV).is_ok());
        assert!(rule.validate("DEBUG", "false", ENV).is_ok());
    }

    #[test]
    fn test_boolean_validation_failure() {
        let rule = RuleType::Boolean;
        let err = rule.validate("DEBUG", "yes", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'DEBUG' must be a boolean (true/false), got: 'yes'"
        );
    }

    #[test]
    fn test_port_validation_success() {
        let rule = RuleType::Port;
        assert!(rule.validate("APP_PORT", "8080", ENV).is_ok());
    }

    #[test]
    fn test_port_validation_invalid_parse() {
        let rule = RuleType::Port;
        let err = rule.validate("APP_PORT", "70000", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'APP_PORT' must be a valid port number (0-65535), got: '70000'"
        );
    }

    #[test]
    fn test_port_validation_zero_error() {
        let rule = RuleType::Port;
        let err = rule.validate("APP_PORT", "0", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'APP_PORT' port cannot be 0"
        );
    }

    #[test]
    fn test_uri_validation_success() {
        let rule = RuleType::Uri;
        assert!(
            rule.validate("URL", "https://github.com/lczerniawski", ENV)
                .is_ok()
        );
    }

    #[test]
    fn test_uri_validation_failure() {
        let rule = RuleType::Uri;
        let err = rule.validate("URL", "not-a-valid-uri", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'URL' must be a valid URI/URL, got: 'not-a-valid-uri'"
        );
    }

    #[test]
    fn test_ip_validation_success() {
        let rule = RuleType::IP;
        assert!(rule.validate("HOST", "127.0.0.1", ENV).is_ok());
        assert!(rule.validate("HOST", "::1", ENV).is_ok());
    }

    #[test]
    fn test_ip_validation_failure() {
        let rule = RuleType::IP;
        let err = rule.validate("HOST", "256.0.0.1", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'HOST' must be a valid IP address, got: '256.0.0.1'"
        );
    }

    #[test]
    fn test_email_validation_success() {
        let rule = RuleType::Email;
        assert!(
            rule.validate("ADMIN_EMAIL", "test@example.com", ENV)
                .is_ok()
        );
    }

    #[test]
    fn test_email_validation_failures() {
        let rule = RuleType::Email;

        let err = rule.validate("ADMIN_EMAIL", "no-at-sign", ENV).unwrap_err();
        assert!(err.to_string().contains("must be a valid email address"));

        let err_start = rule
            .validate("ADMIN_EMAIL", "@example.com", ENV)
            .unwrap_err();
        assert!(
            err_start
                .to_string()
                .contains("must be a valid email address")
        );

        let err_end = rule.validate("ADMIN_EMAIL", "test@", ENV).unwrap_err();
        assert!(
            err_end
                .to_string()
                .contains("must be a valid email address")
        );
    }

    #[test]
    fn test_regex_validation_success() {
        let rule = RuleType::Regex {
            pattern: r"^[A-Z]{3}-\d{3}$".to_string(),
        };
        assert!(rule.validate("SERIAL", "ABC-123", ENV).is_ok());
    }

    #[test]
    fn test_regex_validation_no_match() {
        let rule = RuleType::Regex {
            pattern: r"^[A-Z]{3}-\d{3}$".to_string(),
        };
        let err = rule.validate("SERIAL", "abc-123", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'SERIAL' does not match the required pattern, got: 'abc-123'"
        );
    }

    #[test]
    fn test_regex_validation_invalid_pattern() {
        let rule = RuleType::Regex {
            pattern: "[unclosed-bracket".to_string(),
        };
        let err = rule.validate("SERIAL", "anything", ENV).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[test-env] Key 'SERIAL' has an invalid regex pattern: '[unclosed-bracket'"
        );
    }

    #[test]
    fn validation_rule_constructor_preserves_type_and_required_flag() {
        let rule = ValidationRule::new(RuleType::Boolean, false);
        assert!(!rule.required);
        assert!(matches!(rule.rule_type, RuleType::Boolean));
    }
}
