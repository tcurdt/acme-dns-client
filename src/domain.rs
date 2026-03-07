use crate::errors::AppError;

/// A validated domain name (plain or wildcard like `*.example.com`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain(String);

impl Domain {
    pub fn new(raw: &str) -> Result<Self, AppError> {
        validate(raw)?;
        Ok(Domain(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    /// Returns the base domain (strips leading `*.` for wildcards).
    pub fn base(&self) -> &str {
        if self.is_wildcard() {
            &self.0[2..]
        } else {
            &self.0
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

use std::fmt;

fn validate(raw: &str) -> Result<(), AppError> {
    let base = if let Some(stripped) = raw.strip_prefix("*.") {
        stripped
    } else {
        raw
    };

    if base.is_empty() {
        return Err(AppError::DomainValidation(format!(
            "invalid domain: {:?}",
            raw
        )));
    }

    let labels: Vec<&str> = base.split('.').collect();
    if labels.len() < 2 {
        return Err(AppError::DomainValidation(format!(
            "invalid domain (must have at least two labels): {:?}",
            raw
        )));
    }

    for label in &labels {
        if label.is_empty() {
            return Err(AppError::DomainValidation(format!(
                "invalid domain (empty label): {:?}",
                raw
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(AppError::DomainValidation(format!(
                "invalid domain (invalid characters in label {:?}): {:?}",
                label, raw
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(AppError::DomainValidation(format!(
                "invalid domain (label starts or ends with hyphen): {:?}",
                raw
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_plain_domain() {
        assert!(Domain::new("example.com").is_ok());
        assert!(Domain::new("sub.example.com").is_ok());
        assert!(Domain::new("my-host.example.co.uk").is_ok());
    }

    #[test]
    fn valid_wildcard_domain() {
        let d = Domain::new("*.example.com").unwrap();
        assert!(d.is_wildcard());
        assert_eq!(d.base(), "example.com");
    }

    #[test]
    fn invalid_single_label() {
        assert!(Domain::new("localhost").is_err());
    }

    #[test]
    fn invalid_empty() {
        assert!(Domain::new("").is_err());
        assert!(Domain::new("*.").is_err());
    }

    #[test]
    fn invalid_hyphen_edges() {
        assert!(Domain::new("-bad.example.com").is_err());
        assert!(Domain::new("bad-.example.com").is_err());
    }

    #[test]
    fn invalid_special_chars() {
        assert!(Domain::new("ex_ample.com").is_err());
        assert!(Domain::new("ex ample.com").is_err());
    }

    #[test]
    fn wildcard_not_nested() {
        // `*.*.example.com` should fail because the first label after stripping `*.` is `*`
        assert!(Domain::new("*.*.example.com").is_err());
    }
}
