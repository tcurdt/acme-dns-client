use clap::Parser;

pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME DNS-01 certificate issuance with in-process DNS challenge responder.
#[derive(Parser, Debug)]
#[command(name = "acme-dns-auth", version, about)]
pub struct Args {
    /// Domain name(s) to include in the certificate (repeatable, wildcards supported).
    #[arg(short = 'd', long = "domain", required = true)]
    pub domains: Vec<String>,

    /// ACME directory URL (defaults to Let's Encrypt production).
    #[arg(short = 'p', long = "provider-url", conflicts_with = "staging")]
    pub provider_url: Option<String>,

    /// Use Let's Encrypt staging URL (shorthand for --provider-url with the staging URL).
    #[arg(long = "staging", conflicts_with = "provider_url")]
    pub staging: bool,

    /// Output directory for certificates and account key.
    #[arg(long = "output-dir")]
    pub output_dir: Option<String>,

    /// Path to configuration file (TOML format).
    #[arg(long = "config")]
    pub config: Option<String>,

    /// Email address for ACME account registration.
    #[arg(long = "email")]
    pub email: Option<String>,

    /// IP:PORT for the DNS challenge server to listen on.
    #[arg(long = "listen")]
    pub listen: Option<String>,

    /// Directory to back up existing cert artifacts before promotion.
    #[arg(long = "backup-dir")]
    pub backup_dir: Option<String>,

    /// Overall issuance timeout in seconds (0 = no timeout).
    #[arg(long = "timeout")]
    pub timeout: Option<u64>,

    /// Maximum number of retries for transient ACME failures (0 = no retries).
    #[arg(long = "retries")]
    pub retries: Option<u32>,

    /// Backoff duration in seconds between retries.
    #[arg(long = "retry-backoff")]
    pub retry_backoff: Option<u64>,

    /// Maximum in-flight DNS queries before new ones are refused.
    #[arg(long = "dns-inflight-cap")]
    pub dns_inflight_cap: Option<usize>,
}
