use serde::Deserialize;
use std::path::Path;

use crate::cli::LETSENCRYPT_PRODUCTION;
use crate::errors::AppError;

/// Config file model (TOML).
#[derive(Deserialize, Debug, Default)]
pub struct ConfigFile {
    pub provider_url: Option<String>,
    pub output_dir: Option<String>,
    pub email: Option<String>,
    pub listen: Option<String>,
    pub domains: Option<Vec<String>>,
    pub backup_dir: Option<String>,
    pub timeout: Option<u64>,
    pub retries: Option<u32>,
    pub retry_backoff: Option<u64>,
    pub dns_inflight_cap: Option<usize>,
}

/// Effective runtime configuration after merging CLI > config file > defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub domains: Vec<String>,
    pub provider_url: String,
    pub output_dir: String,
    pub email: Option<String>,
    pub listen: String,
    pub backup_dir: Option<String>,
    /// Overall issuance timeout in seconds; 0 means no timeout.
    pub timeout_secs: u64,
    /// Maximum retries for transient failures; 0 means no retries.
    pub retries: u32,
    /// Backoff between retries in seconds.
    pub retry_backoff_secs: u64,
    /// Maximum concurrent in-flight DNS queries; 0 means no cap.
    pub dns_inflight_cap: usize,
}

impl ConfigFile {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AppError::Config(format!(
                "failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        toml::from_str(&content)
            .map_err(|e| AppError::Config(format!("failed to parse config file: {}", e)))
    }
}

/// Merges CLI arguments with an optional config file, applying defaults.
///
/// Precedence: CLI > config file > defaults.
#[allow(clippy::too_many_arguments)]
pub fn merge(
    cli_domains: Vec<String>,
    cli_provider_url: Option<String>,
    cli_output_dir: Option<String>,
    cli_email: Option<String>,
    cli_listen: Option<String>,
    cli_backup_dir: Option<String>,
    cli_timeout: Option<u64>,
    cli_retries: Option<u32>,
    cli_retry_backoff: Option<u64>,
    cli_dns_inflight_cap: Option<usize>,
    file: Option<ConfigFile>,
) -> Config {
    let file = file.unwrap_or_default();

    let domains = if !cli_domains.is_empty() {
        cli_domains
    } else {
        file.domains.unwrap_or_default()
    };

    let provider_url = cli_provider_url
        .or(file.provider_url)
        .unwrap_or_else(|| LETSENCRYPT_PRODUCTION.to_string());

    let output_dir = cli_output_dir
        .or(file.output_dir)
        .unwrap_or_else(|| ".".to_string());

    let email = cli_email.or(file.email);

    let listen = cli_listen
        .or(file.listen)
        .unwrap_or_else(|| "0.0.0.0:53".to_string());

    let backup_dir = cli_backup_dir.or(file.backup_dir);

    let timeout_secs = cli_timeout.or(file.timeout).unwrap_or(0);
    let retries = cli_retries.or(file.retries).unwrap_or(0);
    let retry_backoff_secs = cli_retry_backoff.or(file.retry_backoff).unwrap_or(5);
    let dns_inflight_cap = cli_dns_inflight_cap.or(file.dns_inflight_cap).unwrap_or(0);

    Config {
        domains,
        provider_url,
        output_dir,
        email,
        listen,
        backup_dir,
        timeout_secs,
        retries,
        retry_backoff_secs,
        dns_inflight_cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_merge(cli_domains: Vec<String>, file: Option<ConfigFile>) -> Config {
        merge(
            cli_domains,
            Some("https://acme.example.com/directory".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            file,
        )
    }

    #[test]
    fn cli_domains_take_precedence() {
        let file = ConfigFile {
            domains: Some(vec!["file.example.com".to_string()]),
            ..Default::default()
        };
        let cfg = base_merge(vec!["cli.example.com".to_string()], Some(file));
        assert_eq!(cfg.domains, vec!["cli.example.com"]);
    }

    #[test]
    fn file_domains_used_when_cli_empty() {
        let file = ConfigFile {
            domains: Some(vec!["file.example.com".to_string()]),
            ..Default::default()
        };
        let cfg = base_merge(vec![], Some(file));
        assert_eq!(cfg.domains, vec!["file.example.com"]);
    }

    #[test]
    fn defaults_applied_when_no_config() {
        let cfg = base_merge(vec!["example.com".to_string()], None);
        assert_eq!(cfg.output_dir, ".");
        assert_eq!(cfg.listen, "0.0.0.0:53");
        assert!(cfg.email.is_none());
    }

    #[test]
    fn cli_output_dir_overrides_file() {
        let file = ConfigFile {
            output_dir: Some("/from/file".to_string()),
            ..Default::default()
        };
        let cfg = merge(
            vec!["example.com".to_string()],
            Some("https://acme.example.com/directory".to_string()),
            Some("/from/cli".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(file),
        );
        assert_eq!(cfg.output_dir, "/from/cli");
    }

    #[test]
    fn file_listen_used_when_cli_absent() {
        let file = ConfigFile {
            listen: Some("127.0.0.1:5353".to_string()),
            ..Default::default()
        };
        let cfg = merge(
            vec!["example.com".to_string()],
            Some("https://acme.example.com/directory".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(file),
        );
        assert_eq!(cfg.listen, "127.0.0.1:5353");
    }

    #[test]
    fn defaults_for_phase2_fields() {
        let cfg = base_merge(vec!["example.com".to_string()], None);
        assert_eq!(cfg.timeout_secs, 0, "default timeout is 0 (no timeout)");
        assert_eq!(cfg.retries, 0, "default retries is 0 (no retries)");
        assert_eq!(cfg.retry_backoff_secs, 5, "default backoff is 5s");
        assert_eq!(
            cfg.dns_inflight_cap, 0,
            "default inflight cap is 0 (no cap)"
        );
    }

    #[test]
    fn cli_timeout_overrides_default() {
        let cfg = merge(
            vec!["example.com".to_string()],
            Some("https://acme.example.com/directory".to_string()),
            None,
            None,
            None,
            None,
            Some(120),
            Some(3),
            Some(10),
            Some(50),
            None,
        );
        assert_eq!(cfg.timeout_secs, 120);
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.retry_backoff_secs, 10);
        assert_eq!(cfg.dns_inflight_cap, 50);
    }

    #[test]
    fn file_phase2_fields_used_when_cli_absent() {
        let file = ConfigFile {
            timeout: Some(60),
            retries: Some(2),
            retry_backoff: Some(8),
            dns_inflight_cap: Some(100),
            ..Default::default()
        };
        let cfg = base_merge(vec!["example.com".to_string()], Some(file));
        assert_eq!(cfg.timeout_secs, 60);
        assert_eq!(cfg.retries, 2);
        assert_eq!(cfg.retry_backoff_secs, 8);
        assert_eq!(cfg.dns_inflight_cap, 100);
    }

    use crate::cli::LETSENCRYPT_STAGING;

    #[test]
    fn default_provider_url_is_letsencrypt_production() {
        let cfg = merge(
            vec!["example.com".to_string()],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(cfg.provider_url, LETSENCRYPT_PRODUCTION);
    }

    #[test]
    fn staging_url_is_set_when_passed() {
        let cfg = merge(
            vec!["example.com".to_string()],
            Some(LETSENCRYPT_STAGING.to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(cfg.provider_url, LETSENCRYPT_STAGING);
    }
}
