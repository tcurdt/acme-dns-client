use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::dns::RecordStore;
use crate::errors::AppError;

// ── Phase 2 runtime config ────────────────────────────────────────────────────

/// Runtime configuration knobs added in Phase 2 (timeout, retry, backoff).
pub struct AcmeConfig {
    /// Maximum retries for transient HTTP/ACME failures; 0 means no retries.
    pub retries: u32,
    /// Seconds to wait between retries.
    pub retry_backoff_secs: u64,
    /// Optional absolute deadline; `None` means no timeout.
    pub deadline: Option<Instant>,
}

impl AcmeConfig {
    /// Returns `true` if the deadline has passed.
    fn is_timed_out(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Sleeps for `retry_backoff_secs` or until the deadline, whichever comes first.
    /// Returns `Err(AppError::Timeout)` if the deadline expires during the sleep.
    fn sleep_backoff(&self, shutdown: &AtomicBool) -> Result<(), AppError> {
        let end = Instant::now() + Duration::from_secs(self.retry_backoff_secs);
        loop {
            if shutdown.load(Ordering::SeqCst) {
                return Err(AppError::Interrupted);
            }
            let now = Instant::now();
            if now >= end {
                break;
            }
            if self.deadline.is_some_and(|d| now >= d) {
                return Err(AppError::Timeout("issuance deadline exceeded".to_string()));
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }
}

// ── ACME directory ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

// ── Order / Authorization types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeOrder {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeAuthorization {
    identifier: AcmeIdentifier,
    status: String,
    challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Deserialize)]
struct AcmeIdentifier {
    value: String,
}

#[derive(Debug, Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: String,
}

// ── Account key ───────────────────────────────────────────────────────────────

/// ECDSA P-256 account key used to sign ACME JWS requests.
pub struct AccountKey {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
    pkcs8_der: Vec<u8>,
}

impl AccountKey {
    /// Generate a new random ECDSA P-256 key pair.
    pub fn generate() -> Result<Self, AppError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| AppError::Acme("failed to generate account key".to_string()))?;
        let der = pkcs8.as_ref().to_vec();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| AppError::Acme("failed to parse generated account key".to_string()))?;
        Ok(Self {
            key_pair,
            rng,
            pkcs8_der: der,
        })
    }

    /// Load a key from PKCS#8 PEM text.
    pub fn from_pem(pem: &str) -> Result<Self, AppError> {
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = B64_STD
            .decode(body.trim())
            .map_err(|e| AppError::Acme(format!("failed to decode account key PEM: {}", e)))?;
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| AppError::Acme("failed to parse account key from PEM".to_string()))?;
        Ok(Self {
            key_pair,
            rng,
            pkcs8_der: der,
        })
    }

    /// Encode the private key as PKCS#8 PEM text.
    pub fn to_pem(&self) -> String {
        let encoded = B64_STD.encode(&self.pkcs8_der);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        let mut i = 0;
        while i < encoded.len() {
            let end = (i + 64).min(encoded.len());
            pem.push_str(&encoded[i..end]);
            pem.push('\n');
            i += 64;
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }

    /// Returns the base64url-encoded (x, y) coordinates of the public key.
    fn jwk_xy(&self) -> (String, String) {
        let pub_key = self.key_pair.public_key().as_ref();
        // Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
        let (x, y) = pub_key[1..].split_at(32);
        (B64_URL.encode(x), B64_URL.encode(y))
    }

    /// Computes the RFC 7638 JWK thumbprint (base64url SHA-256 of canonical JWK).
    pub fn thumbprint(&self) -> Result<String, AppError> {
        let (x, y) = self.jwk_xy();
        // Alphabetically sorted, minimal fields per RFC 7638
        #[derive(Serialize)]
        struct Thumb<'a> {
            crv: &'a str,
            kty: &'a str,
            x: &'a str,
            y: &'a str,
        }
        let json = serde_json::to_vec(&Thumb {
            crv: "P-256",
            kty: "EC",
            x: &x,
            y: &y,
        })
        .map_err(|e| AppError::Acme(format!("failed to serialize JWK thumbprint: {}", e)))?;
        Ok(B64_URL.encode(digest(&SHA256, &json).as_ref()))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, AppError> {
        self.key_pair
            .sign(&self.rng, data)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| AppError::Acme("ECDSA signing failed".to_string()))
    }
}

// ── JOSE/JWS helpers ──────────────────────────────────────────────────────────

/// Builds a JWS (JSON Web Signature) object for an ACME POST request.
///
/// When `kid` is `None`, embeds the full JWK (used for account creation).
/// When `kid` is `Some(url)`, uses the account URL as key ID (subsequent requests).
/// When `payload` is `None`, produces an empty payload (POST-as-GET).
fn build_jose(
    payload: Option<&Value>,
    key: &AccountKey,
    kid: Option<&str>,
    nonce: &str,
    url: &str,
) -> Result<Value, AppError> {
    let (x, y) = key.jwk_xy();
    let protected_obj: Value = match kid {
        Some(kid) => serde_json::json!({
            "alg": "ES256",
            "kid": kid,
            "nonce": nonce,
            "url": url,
        }),
        None => serde_json::json!({
            "alg": "ES256",
            "jwk": { "crv": "P-256", "kty": "EC", "use": "sig", "x": x, "y": y },
            "nonce": nonce,
            "url": url,
        }),
    };

    let protected_bytes = serde_json::to_vec(&protected_obj)
        .map_err(|e| AppError::Acme(format!("failed to encode protected header: {}", e)))?;
    let protected = B64_URL.encode(&protected_bytes);

    let payload_str = match payload {
        Some(p) => {
            let bytes = serde_json::to_vec(p)
                .map_err(|e| AppError::Acme(format!("failed to encode payload: {}", e)))?;
            B64_URL.encode(&bytes)
        }
        None => String::new(),
    };

    let signing_input = format!("{}.{}", protected, payload_str);
    let signature = B64_URL.encode(key.sign(signing_input.as_bytes())?);

    Ok(serde_json::json!({
        "protected": protected,
        "payload": payload_str,
        "signature": signature,
    }))
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

struct PostResult {
    location: Option<String>,
    nonce: Option<String>,
    body: String,
}

fn http_get_json(url: &str) -> Result<Value, AppError> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| AppError::Acme(format!("GET {} failed: {}", url, e)))?;
    resp.into_json()
        .map_err(|e| AppError::Acme(format!("failed to parse JSON from {}: {}", url, e)))
}

fn http_post_jose(url: &str, jose: &Value) -> Result<PostResult, AppError> {
    let resp = match ureq::post(url)
        .set("Content-Type", "application/jose+json")
        .send_json(jose.clone())
    {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            return Err(AppError::Acme(format!(
                "ACME server returned {} at {}: {}",
                code, url, body
            )));
        }
        Err(e) => {
            return Err(AppError::Acme(format!("HTTP error at {}: {}", url, e)));
        }
    };

    let location = resp.header("Location").map(|s| s.to_string());
    let nonce = resp.header("Replay-Nonce").map(|s| s.to_string());
    let body = resp
        .into_string()
        .map_err(|e| AppError::Acme(format!("failed to read response body: {}", e)))?;
    Ok(PostResult {
        location,
        nonce,
        body,
    })
}

fn get_nonce(new_nonce_url: &str) -> Result<String, AppError> {
    let resp = ureq::head(new_nonce_url)
        .call()
        .map_err(|e| AppError::Acme(format!("failed to get ACME nonce: {}", e)))?;
    resp.header("Replay-Nonce")
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Acme("no Replay-Nonce in nonce response".to_string()))
}

fn refresh_nonce(current: Option<String>, new_nonce_url: &str) -> Result<String, AppError> {
    match current {
        Some(n) => Ok(n),
        None => get_nonce(new_nonce_url),
    }
}

/// Calls `http_post_jose` with up to `config.retries` retries on transient errors.
///
/// ACME 5xx responses and network errors are considered transient.
/// 4xx errors (bad request, unauthorized, etc.) are fatal and not retried.
fn http_post_jose_with_retry(
    url: &str,
    jose: &Value,
    config: &AcmeConfig,
    shutdown: &AtomicBool,
) -> Result<PostResult, AppError> {
    let mut last_err = None;
    for attempt in 0..=config.retries {
        if shutdown.load(Ordering::SeqCst) {
            return Err(AppError::Interrupted);
        }
        if config.is_timed_out() {
            return Err(AppError::Timeout("issuance deadline exceeded".to_string()));
        }
        match http_post_jose(url, jose) {
            Ok(r) => return Ok(r),
            Err(e) => {
                // Only retry on errors that look transient (network/server-side)
                let is_transient = match &e {
                    AppError::Acme(msg) => {
                        // Retry on 5xx or network errors; don't retry 4xx
                        msg.contains("500")
                            || msg.contains("502")
                            || msg.contains("503")
                            || msg.contains("504")
                            || msg.contains("HTTP error at")
                    }
                    _ => false,
                };
                if !is_transient || attempt >= config.retries {
                    return Err(e);
                }
                log::warn!(
                    "Transient error on attempt {}/{}: {}; retrying in {}s",
                    attempt + 1,
                    config.retries,
                    e,
                    config.retry_backoff_secs
                );
                last_err = Some(e);
                config.sleep_backoff(shutdown)?;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AppError::Acme("retry loop exhausted".to_string())))
}

// ── DNS-01 challenge value ────────────────────────────────────────────────────

/// Computes the DNS-01 TXT record value: `BASE64URL(SHA256(token + "." + thumbprint))`.
///
/// This is the value that must appear at `_acme-challenge.<domain>` during validation.
pub fn dns01_txt_value(token: &str, thumbprint: &str) -> String {
    let key_auth = format!("{}.{}", token, thumbprint);
    B64_URL.encode(digest(&SHA256, key_auth.as_bytes()).as_ref())
}

// ── CSR generation ────────────────────────────────────────────────────────────

/// Generates a PKCS#10 CSR for the given domain names.
///
/// Returns `(cert_key_der, csr_der)` – the certificate private key in PKCS#8 DER
/// and the CSR in DER format.
fn generate_csr(domains: &[String]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair as RcgenKeyPair};

    let key_pair = RcgenKeyPair::generate()
        .map_err(|e| AppError::Acme(format!("failed to generate cert key: {}", e)))?;
    let mut params = CertificateParams::new(domains.to_vec())
        .map_err(|e| AppError::Acme(format!("failed to create cert params: {}", e)))?;
    params.distinguished_name = DistinguishedName::new();

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| AppError::Acme(format!("failed to generate CSR: {}", e)))?;

    let key_der = key_pair.serialize_der();
    let csr_der = csr.der().to_vec();
    Ok((key_der, csr_der))
}

/// Converts a raw DER private key to PKCS#8 PEM text.
pub fn key_der_to_pem(der: &[u8]) -> String {
    let encoded = B64_STD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + 64).min(encoded.len());
        pem.push_str(&encoded[i..end]);
        pem.push('\n');
        i += 64;
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

// ── Order polling ─────────────────────────────────────────────────────────────

const POLL_MAX: u32 = 30;

#[allow(clippy::too_many_arguments)]
fn poll_order(
    order_url: &str,
    key: &AccountKey,
    account_url: &str,
    new_nonce_url: &str,
    nonce: &mut String,
    wait_for: &[&str],
    shutdown: &AtomicBool,
    config: &AcmeConfig,
) -> Result<AcmeOrder, AppError> {
    for attempt in 0..POLL_MAX {
        if shutdown.load(Ordering::SeqCst) {
            return Err(AppError::Interrupted);
        }
        if config.is_timed_out() {
            return Err(AppError::Timeout(
                "timed out waiting for ACME order".to_string(),
            ));
        }
        if attempt > 0 {
            // Sleep in short intervals to remain responsive to shutdown/timeout
            for _ in 0..50 {
                thread::sleep(Duration::from_millis(100));
                if shutdown.load(Ordering::SeqCst) {
                    return Err(AppError::Interrupted);
                }
                if config.is_timed_out() {
                    return Err(AppError::Timeout(
                        "timed out waiting for ACME order".to_string(),
                    ));
                }
            }
        }

        let jose = build_jose(None, key, Some(account_url), nonce, order_url)?;
        let result = http_post_jose(order_url, &jose)?;
        *nonce = refresh_nonce(result.nonce, new_nonce_url)?;

        let order: AcmeOrder = serde_json::from_str(&result.body)
            .map_err(|e| AppError::Acme(format!("failed to parse order status: {}", e)))?;

        log::debug!(
            "Order poll {}/{}: status={}",
            attempt + 1,
            POLL_MAX,
            order.status
        );

        if order.status == "invalid" {
            return Err(AppError::Acme(
                "ACME order failed with status 'invalid'".to_string(),
            ));
        }
        if wait_for.contains(&order.status.as_str()) {
            return Ok(order);
        }
    }

    Err(AppError::Acme(format!(
        "timed out waiting for ACME order to reach status {:?}",
        wait_for
    )))
}

// ── Main ACME issuance flow ───────────────────────────────────────────────────

/// Result of a successful ACME issuance.
#[derive(Debug)]
pub struct IssuanceResult {
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// DER-encoded certificate private key (PKCS#8).
    pub cert_key_der: Vec<u8>,
}

/// Runs the full ACME DNS-01 issuance flow.
///
/// Loads or generates an account key at `<output_dir>/account.key.pem`, creates
/// or reuses an ACME account, creates an order for `domains`, publishes DNS-01
/// challenge TXT records via `store`, waits for validation, finalizes, and
/// downloads the certificate chain.
pub fn run_acme(
    directory_url: &str,
    domains: &[String],
    email: Option<&str>,
    output_dir: &str,
    store: &RecordStore,
    shutdown: &AtomicBool,
    config: &AcmeConfig,
) -> Result<IssuanceResult, AppError> {
    if shutdown.load(Ordering::SeqCst) {
        return Err(AppError::Interrupted);
    }
    if config.is_timed_out() {
        return Err(AppError::Timeout("issuance deadline exceeded".to_string()));
    }

    // Step 1: fetch directory
    log::info!("Fetching ACME directory from {}", directory_url);
    let dir_json = http_get_json(directory_url)?;
    let dir: AcmeDirectory = serde_json::from_value(dir_json)
        .map_err(|e| AppError::Acme(format!("failed to parse ACME directory: {}", e)))?;

    // Step 2: load or generate account key
    let key_path = Path::new(output_dir).join("account.key.pem");
    let account_key = if key_path.exists() {
        log::info!("Loading existing account key from {}", key_path.display());
        let pem = fs::read_to_string(&key_path)
            .map_err(|e| AppError::Acme(format!("failed to read account key: {}", e)))?;
        AccountKey::from_pem(&pem)?
    } else {
        log::info!("Generating new account key");
        let key = AccountKey::generate()?;
        fs::create_dir_all(output_dir)
            .map_err(|e| AppError::Acme(format!("failed to create output dir: {}", e)))?;
        fs::write(&key_path, key.to_pem())
            .map_err(|e| AppError::Acme(format!("failed to write account key: {}", e)))?;
        log::info!("Saved account key to {}", key_path.display());
        key
    };

    let thumbprint = account_key.thumbprint()?;

    // Step 3: register or recover ACME account
    let mut nonce = get_nonce(&dir.new_nonce)?;
    let contacts: Vec<String> = email
        .map(|e| vec![format!("mailto:{}", e)])
        .unwrap_or_default();
    let contact_refs: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let account_payload = serde_json::json!({
        "termsOfServiceAgreed": true,
        "contact": contact_refs,
    });
    let jose = build_jose(
        Some(&account_payload),
        &account_key,
        None,
        &nonce,
        &dir.new_account,
    )?;
    log::info!("Registering/looking up ACME account at {}", dir.new_account);
    let acct = http_post_jose_with_retry(&dir.new_account, &jose, config, shutdown)?;
    let account_url = acct
        .location
        .ok_or_else(|| AppError::Acme("no account URL in registration response".to_string()))?;
    nonce = refresh_nonce(acct.nonce, &dir.new_nonce)?;
    log::info!("ACME account URL: {}", account_url);

    // Step 4: create order
    let identifiers: Vec<Value> = domains
        .iter()
        .map(|d| serde_json::json!({ "type": "dns", "value": d }))
        .collect();
    let order_payload = serde_json::json!({ "identifiers": identifiers });
    let jose = build_jose(
        Some(&order_payload),
        &account_key,
        Some(&account_url),
        &nonce,
        &dir.new_order,
    )?;
    log::info!("Creating ACME order for domains: {:?}", domains);
    let order_resp = http_post_jose_with_retry(&dir.new_order, &jose, config, shutdown)?;
    let order_url = order_resp
        .location
        .ok_or_else(|| AppError::Acme("no order URL in order response".to_string()))?;
    nonce = refresh_nonce(order_resp.nonce, &dir.new_nonce)?;
    let order: AcmeOrder = serde_json::from_str(&order_resp.body)
        .map_err(|e| AppError::Acme(format!("failed to parse order: {}", e)))?;
    log::info!("Order created: {} (status: {})", order_url, order.status);

    // Step 5: process authorizations and publish DNS-01 TXT records
    let mut challenge_urls: Vec<String> = Vec::new();
    for auth_url in &order.authorizations {
        let jose = build_jose(None, &account_key, Some(&account_url), &nonce, auth_url)?;
        let auth_resp = http_post_jose_with_retry(auth_url, &jose, config, shutdown)?;
        nonce = refresh_nonce(auth_resp.nonce, &dir.new_nonce)?;

        let auth: AcmeAuthorization = serde_json::from_str(&auth_resp.body)
            .map_err(|e| AppError::Acme(format!("failed to parse authorization: {}", e)))?;

        log::info!(
            "Authorization for {} (status: {})",
            auth.identifier.value,
            auth.status
        );

        if auth.status == "valid" {
            log::info!("Authorization already valid, skipping challenge");
            continue;
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.challenge_type == "dns-01")
            .ok_or_else(|| {
                AppError::Acme(format!(
                    "no dns-01 challenge found for {}",
                    auth.identifier.value
                ))
            })?;

        if challenge.status == "valid" {
            log::info!("Challenge already valid for {}", auth.identifier.value);
            continue;
        }

        let txt_value = dns01_txt_value(&challenge.token, &thumbprint);
        let record_name = format!("_acme-challenge.{}", auth.identifier.value);
        log::info!("Publishing TXT {} = {}", record_name, txt_value);
        store.insert(&record_name, &txt_value);
        challenge_urls.push(challenge.url.clone());
    }

    // Step 6: notify ACME server that challenges are ready
    let empty = serde_json::json!({});
    for challenge_url in &challenge_urls {
        let jose = build_jose(
            Some(&empty),
            &account_key,
            Some(&account_url),
            &nonce,
            challenge_url,
        )?;
        log::info!("Notifying challenge ready: {}", challenge_url);
        let result = http_post_jose_with_retry(challenge_url, &jose, config, shutdown)?;
        nonce = refresh_nonce(result.nonce, &dir.new_nonce)?;
    }

    // Step 7: poll until order is ready for finalization
    log::info!("Waiting for ACME order to become ready...");
    let ready_order = poll_order(
        &order_url,
        &account_key,
        &account_url,
        &dir.new_nonce,
        &mut nonce,
        &["ready", "valid"],
        shutdown,
        config,
    )?;

    // Step 8: generate CSR and finalize
    log::info!("Generating CSR and finalizing order");
    let (cert_key_der, csr_der) = generate_csr(domains)?;
    let finalize_payload = serde_json::json!({ "csr": B64_URL.encode(&csr_der) });
    let jose = build_jose(
        Some(&finalize_payload),
        &account_key,
        Some(&account_url),
        &nonce,
        &ready_order.finalize,
    )?;
    let fin_resp = http_post_jose_with_retry(&ready_order.finalize, &jose, config, shutdown)?;
    nonce = refresh_nonce(fin_resp.nonce, &dir.new_nonce)?;

    // Step 9: poll until certificate is available
    log::info!("Waiting for ACME certificate...");
    let valid_order = poll_order(
        &order_url,
        &account_key,
        &account_url,
        &dir.new_nonce,
        &mut nonce,
        &["valid"],
        shutdown,
        config,
    )?;

    let cert_url = valid_order
        .certificate
        .ok_or_else(|| AppError::Acme("no certificate URL in completed order".to_string()))?;

    // Step 10: download certificate chain
    log::info!("Downloading certificate from {}", cert_url);
    let jose = build_jose(None, &account_key, Some(&account_url), &nonce, &cert_url)?;
    let cert_resp = http_post_jose_with_retry(&cert_url, &jose, config, shutdown)?;
    let cert_pem = cert_resp.body;
    log::info!("Certificate chain downloaded successfully");

    Ok(IssuanceResult {
        cert_pem,
        cert_key_der,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns01_value_is_base64url_without_padding() {
        let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
        let thumbprint = "THUMBPRINT";
        let result = dns01_txt_value(token, thumbprint);
        assert!(!result.contains('+'), "must not contain '+'");
        assert!(!result.contains('/'), "must not contain '/'");
        assert!(!result.contains('='), "must not contain '='");
        assert!(!result.is_empty());
    }

    #[test]
    fn account_key_pem_roundtrip() {
        let key = AccountKey::generate().unwrap();
        let pem = key.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        let key2 = AccountKey::from_pem(&pem).unwrap();
        assert_eq!(key.pkcs8_der, key2.pkcs8_der);
    }

    #[test]
    fn account_key_thumbprint_is_base64url() {
        let key = AccountKey::generate().unwrap();
        let thumb = key.thumbprint().unwrap();
        assert!(!thumb.contains('+'));
        assert!(!thumb.contains('/'));
        assert!(!thumb.contains('='));
        assert!(!thumb.is_empty());
    }

    #[test]
    fn key_der_to_pem_format() {
        let key = AccountKey::generate().unwrap();
        let pem = key_der_to_pem(&key.pkcs8_der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn csr_single_domain() {
        let domains = vec!["example.com".to_string()];
        let (key_der, csr_der) = generate_csr(&domains).unwrap();
        assert!(!key_der.is_empty());
        assert!(!csr_der.is_empty());
    }

    #[test]
    fn run_acme_returns_interrupted_when_shutdown_preset() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let store = crate::dns::RecordStore::new();
        let shutdown = Arc::new(AtomicBool::new(true));
        let config = AcmeConfig {
            retries: 0,
            retry_backoff_secs: 0,
            deadline: None,
        };
        let result = run_acme(
            "http://127.0.0.1:1/dir",
            &["example.com".to_string()],
            None,
            "/tmp",
            &store,
            &shutdown,
            &config,
        );
        assert!(
            matches!(result, Err(AppError::Interrupted)),
            "expected Interrupted"
        );
    }

    #[test]
    fn run_acme_returns_timeout_when_deadline_already_passed() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        let store = crate::dns::RecordStore::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        // Deadline in the past
        let config = AcmeConfig {
            retries: 0,
            retry_backoff_secs: 0,
            deadline: Some(Instant::now() - Duration::from_secs(1)),
        };
        let result = run_acme(
            "http://127.0.0.1:1/dir",
            &["example.com".to_string()],
            None,
            "/tmp",
            &store,
            &shutdown,
            &config,
        );
        assert!(
            matches!(result, Err(AppError::Timeout(_))),
            "expected Timeout, got {:?}",
            result
        );
    }

    #[test]
    fn csr_multiple_domains_including_wildcard() {
        // M4: multi-domain single-order run — CSR must include all SANs
        let domains = vec![
            "*.example.com".to_string(),
            "example.com".to_string(),
            "sub.example.com".to_string(),
        ];
        let (key_der, csr_der) = generate_csr(&domains).unwrap();
        assert!(!key_der.is_empty());
        assert!(!csr_der.is_empty());
    }
}
