use clap::Parser;

pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME DNS-01 certificate issuance with in-process DNS challenge responder.
#[derive(Parser, Debug)]
#[command(name = "acme-dns-client", version, about)]
pub struct Args {
    /// Domain name(s) to include in the certificate (repeatable, wildcards supported).
    /// Optional with `--config`, which can list them as `domains`.
    #[arg(short = 'd', long = "domain", required_unless_present = "config")]
    pub domains: Vec<String>,

    /// ACME directory URL (default: `https://acme-v02.api.letsencrypt.org/directory`).
    #[arg(short = 'p', long = "provider-url", conflicts_with = "staging")]
    pub provider_url: Option<String>,

    /// Use Let's Encrypt staging URL (default: disabled).
    #[arg(long = "staging", conflicts_with = "provider_url")]
    pub staging: bool,

    /// Output directory for certificates and account key (default: current directory `.`).
    #[arg(long = "output-dir")]
    pub output_dir: Option<String>,

    /// Path to configuration file (TOML format).
    #[arg(long = "config")]
    pub config: Option<String>,

    /// Email address for ACME account registration.
    #[arg(long = "email")]
    pub email: Option<String>,

    /// IP:PORT for the DNS challenge server to listen on (default: `0.0.0.0:53`).
    #[arg(long = "listen")]
    pub listen: Option<String>,

    /// Directory to back up existing cert artifacts before promotion (default: disabled).
    #[arg(long = "backup-dir")]
    pub backup_dir: Option<String>,

    /// Overall issuance timeout in seconds (default: `0`, meaning no timeout).
    #[arg(long = "timeout")]
    pub timeout: Option<u64>,

    /// Maximum retries for transient ACME failures (default: `0`, meaning no retries).
    #[arg(long = "retries")]
    pub retries: Option<u32>,

    /// Backoff in seconds between retries (default: `5`).
    #[arg(long = "retry-backoff")]
    pub retry_backoff: Option<u64>,

    /// Maximum in-flight DNS queries before refusing new ones (default: `0`, no cap).
    #[arg(long = "dns-inflight-cap")]
    pub dns_inflight_cap: Option<usize>,

    /// Skip renewal if the existing certificate expires more than this many days from now (default: `7`).
    #[arg(long = "renew-days-before-expire", default_value = "7")]
    pub renew_days_before_expire: u64,

    /// Force renewal even if the certificate is still recent enough.
    #[arg(long = "force")]
    pub force: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_required_without_config() {
        assert!(Args::try_parse_from(["acme-dns-client"]).is_err());
    }

    #[test]
    fn config_alone_is_accepted() {
        let args = Args::try_parse_from(["acme-dns-client", "--config", "x.toml"]).unwrap();
        assert!(args.domains.is_empty());
        assert_eq!(args.config.as_deref(), Some("x.toml"));
    }

    #[test]
    fn domains_on_cli_with_config() {
        let args = Args::try_parse_from([
            "acme-dns-client",
            "--config",
            "x.toml",
            "-d",
            "*.example.com",
        ])
        .unwrap();
        assert_eq!(args.domains, vec!["*.example.com"]);
    }
}
