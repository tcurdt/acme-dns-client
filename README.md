`acme-dns-client` is a Rust CLI for issuing ACME certificates (including wildcards)
with DNS-01 challenges, without giving your issuance host broad DNS provider API
credentials or exposing your custom DNS server for 24/7.

## Why this exists

Most DNS-01 automation requires long-lived DNS API credentials on the machine that
issues certificates. If that host is compromised, your full DNS zone can be at
risk.

The next best thing is to run DNS server just for the DNS-01 verification.
But then you have another service exposed to internet.

This project uses a narrower trust model:

- You delegate only challenge lookups via NS (`_acme-challenge.<domain>`)
- The tool runs a short-lived in-process authoritative DNS server
- It serves challenge TXT records only during issuance
- It writes the certificates to disk

## How to use it

### 1) Configure DNS delegation once

For each base domain, delegate `_acme-challenge` to your issuance host:

```dns
_acme-challenge.example.com.  IN NS   acme.example.com.
acme.example.com.             IN A    <your-public-ipv4>
acme.example.com.             IN AAAA <your-public-ipv6>
```

The program prints the exact records it expects and verifies delegation before
starting ACME issuance.

### 2) Run a staging issuance first

```bash
acme-dns-client \
  --staging \
  -d "*.example.com" \
  -d "example.com" \
  --email ops@example.com \
  --output-dir ./certs
```

Then switch to production by removing `--staging` (or setting `--provider-url`).

### 3) Optional config file

You can keep defaults in TOML and still override from CLI:

```toml
provider_url = "https://acme-v02.api.letsencrypt.org/directory"
output_dir = "./certs"
email = "ops@example.com"
listen = "0.0.0.0:53"
domains = ["*.example.com", "example.com"]
backup_dir = "./certs-backup"
timeout = 120
retries = 3
retry_backoff = 5
dns_inflight_cap = 200
```

Use with:

```bash
acme-dns-client --config ./acme-dns-client.toml
```

## CLI options

Core options:

- `-d, --domain <DOMAIN>`: Domain(s) to include (repeatable, wildcard supported)
- `-p, --provider-url <URL>`: ACME directory URL
- `--staging`: Use Let's Encrypt staging URL
- `--output-dir <PATH>`: Where to store cert/account artifacts
- `--config <PATH>`: TOML config file
- `--email <EMAIL>`: ACME account email
- `--listen <IP:PORT>`: DNS server bind address (default `0.0.0.0:53`)
- `--backup-dir <PATH>`: Backup old `cert.pem`/`key.pem` before replacement
- `--timeout <SECONDS>`: Overall issuance timeout (`0` disables)
- `--retries <N>`: Retries for transient ACME failures (`0` disables)
- `--retry-backoff <SECONDS>`: Delay between retries
- `--dns-inflight-cap <N>`: Max in-flight DNS queries (`0` disables)

### Notes

- Binding to `:53` may require elevated privileges/capabilities.
- If you need a non-privileged port during testing, use `--listen` and map the incoming port accordingly.

## How to build

Build from source:

```bash
just build
```

## Installation options

### 1) Prebuilt binary (GitHub Releases)

Download a release archive from:

- `https://github.com/tcurdt/acme-dns-client/releases`

Extract it and place `acme-dns-client` on your `PATH`.

### 2) Homebrew

```bash
brew install tcurdt/tap/acme-dns-client
```

### 3) Nix flake

Run without installing:

```bash
nix run github:tcurdt/acme-dns-client -- --help
```

Build from flake:

```bash
nix build .
```

## License

Licensed under Apache-2.0. See `LICENSE.txt`.
