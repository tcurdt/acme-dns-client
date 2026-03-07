use std::net::IpAddr;
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use acme_dns_client::acme::{AcmeConfig, IssuanceResult, key_der_to_pem, run_acme};
use acme_dns_client::artifacts::{cleanup_staging, promote, staging_dir, write_staged};
use acme_dns_client::cli::{Args, LETSENCRYPT_STAGING};
use acme_dns_client::config::{ConfigFile, merge};
use acme_dns_client::dns::{DnsServer, RecordStore, check_ns_delegation};
use acme_dns_client::domain::Domain;
use acme_dns_client::errors::{AppError, exit_code};
use clap::Parser;

/// Fetches the external public IPv4 address via ipv4.icanhazip.com.
/// Returns `None` on any network or parse error.
fn fetch_external_ipv4() -> Option<IpAddr> {
    let body = ureq::get("https://ipv4.icanhazip.com")
        .call()
        .ok()?
        .into_string()
        .ok()?;
    IpAddr::from_str(body.trim()).ok()
}

/// Fetches the external public IPv6 address via ipv6.icanhazip.com.
/// Returns `None` on any network or parse error (including no IPv6 connectivity).
fn fetch_external_ipv6() -> Option<IpAddr> {
    let body = ureq::get("https://ipv6.icanhazip.com")
        .call()
        .ok()?
        .into_string()
        .ok()?;
    IpAddr::from_str(body.trim()).ok()
}

fn run() -> Result<(), AppError> {
    env_logger::init();

    let args = Args::parse();

    // Resolve --staging into provider_url before merging
    let provider_url = if args.staging {
        Some(LETSENCRYPT_STAGING.to_string())
    } else {
        args.provider_url
    };

    let config_file = args
        .config
        .as_deref()
        .map(|path| ConfigFile::load(Path::new(path)))
        .transpose()?;

    let config = merge(
        args.domains,
        provider_url,
        args.output_dir,
        args.email,
        args.listen,
        args.backup_dir,
        args.timeout,
        args.retries,
        args.retry_backoff,
        args.dns_inflight_cap,
        config_file,
    );

    // Validate all domain names
    let domains: Result<Vec<Domain>, AppError> =
        config.domains.iter().map(|d| Domain::new(d)).collect();
    let domains = domains?;

    if domains.is_empty() {
        return Err(AppError::Config(
            "at least one domain must be specified".to_string(),
        ));
    }

    log::info!("Provider URL: {}", config.provider_url);
    log::info!(
        "Domains: {}",
        domains
            .iter()
            .map(|d| d.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    log::info!("Output dir: {}", config.output_dir);
    log::info!("Listen: {}", config.listen);
    if config.timeout_secs > 0 {
        log::info!("Timeout: {}s", config.timeout_secs);
    }
    if config.retries > 0 {
        log::info!(
            "Retries: {} (backoff: {}s)",
            config.retries,
            config.retry_backoff_secs
        );
    }
    if config.dns_inflight_cap > 0 {
        log::info!("DNS inflight cap: {}", config.dns_inflight_cap);
    }

    // Build optional deadline from timeout
    let deadline = if config.timeout_secs > 0 {
        Some(Instant::now() + Duration::from_secs(config.timeout_secs))
    } else {
        None
    };

    // Set up graceful shutdown flag; register SIGINT/SIGTERM handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        log::warn!("Shutdown signal received, aborting...");
        shutdown_flag.store(true, Ordering::SeqCst);
    })
    .map_err(|e| AppError::Config(format!("failed to set signal handler: {}", e)))?;

    // Start in-process DNS challenge server
    let store = Arc::new(RecordStore::new());
    let listen_addr: std::net::SocketAddr = config.listen.parse().map_err(|e| {
        AppError::Config(format!("invalid listen address '{}': {}", config.listen, e))
    })?;
    let mut dns_server = DnsServer::new(listen_addr, Arc::clone(&store), config.dns_inflight_cap);
    let bound_addr = dns_server.start()?;
    log::info!("DNS challenge server listening on {}", bound_addr);

    // Fetch external IPs for the NS delegation hint.
    let ipv4 = fetch_external_ipv4();
    let ipv6 = fetch_external_ipv6();
    if ipv4.is_none() && ipv6.is_none() {
        eprintln!(
            "Warning: could not determine external IP via icanhazip.com; \
             replace the placeholder IPs below with your actual public IP(s)."
        );
    }

    // Print the NS delegation records the operator must add to their parent zone.
    // Use eprintln so this is always visible regardless of RUST_LOG level.
    eprintln!();
    eprintln!("Ensure these DNS records are present in your parent zone:");
    eprintln!();
    for domain in &domains {
        let base = domain.base();
        let ns_host = format!("acme.{}.", base);
        eprintln!("  _acme-challenge.{}.  IN NS  {}", base, ns_host);
        match ipv4 {
            Some(ip) => eprintln!("  {}  IN A     {}", ns_host, ip),
            None => eprintln!("  {}  IN A     <your-ipv4-address>", ns_host),
        }
        if let Some(ip) = ipv6 {
            eprintln!("  {}  IN AAAA  {}", ns_host, ip);
        }
        eprintln!();
    }

    // Verify NS delegation is in place before starting ACME flow.
    // Collect all failures first so the operator sees all missing records at once.
    let resolver = "8.8.8.8:53";
    let mut delegation_errors: Vec<String> = Vec::new();
    for domain in &domains {
        let ns_host = format!("acme.{}.", domain.base());
        if let Err(e) = check_ns_delegation(domain.base(), &ns_host, resolver) {
            delegation_errors.push(format!("  {}", e));
        }
    }
    if !delegation_errors.is_empty() {
        dns_server.stop();
        return Err(AppError::Dns(format!(
            "NS delegation check failed:\n{}",
            delegation_errors.join("\n")
        )));
    }
    eprintln!("NS delegation verified. Starting ACME issuance...");

    // Run ACME issuance
    let domain_strs: Vec<String> = domains.iter().map(|d| d.as_str().to_string()).collect();
    let acme_config = AcmeConfig {
        retries: config.retries,
        retry_backoff_secs: config.retry_backoff_secs,
        deadline,
    };
    let result = run_acme(
        &config.provider_url,
        &domain_strs,
        config.email.as_deref(),
        &config.output_dir,
        &store,
        &shutdown,
        &acme_config,
    );

    // Stop DNS server regardless of ACME outcome
    dns_server.stop();

    let output_dir = Path::new(&config.output_dir);
    std::fs::create_dir_all(output_dir)
        .map_err(|e| AppError::Output(format!("failed to create output directory: {}", e)))?;

    // Create a unique staging directory for this run (timestamped to avoid conflicts)
    let staging = staging_dir(output_dir);

    match result {
        Err(AppError::Interrupted) => {
            // Clean up staging files; leave live files unchanged
            cleanup_staging(&staging);
            log::warn!("Issuance aborted; staging files cleaned up");
            return Err(AppError::Interrupted);
        }
        Err(e) => {
            // Clean up any staging files; leave live files unchanged
            cleanup_staging(&staging);
            return Err(e);
        }
        Ok(IssuanceResult {
            cert_pem,
            cert_key_der,
        }) => {
            let key_pem = key_der_to_pem(&cert_key_der);

            // Stage artifacts first; only promote on full success
            write_staged(&staging, &cert_pem, &key_pem)?;

            let backup_dir = config.backup_dir.as_deref().map(Path::new);
            if let Err(e) = promote(output_dir, &staging, backup_dir) {
                cleanup_staging(&staging);
                return Err(e);
            }

            log::info!("Certificate artifacts promoted to {}", output_dir.display());
        }
    }

    log::info!("Issuance complete");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(exit_code(&e));
    }
}
