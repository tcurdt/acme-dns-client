set quiet := true

default:
    just --list

check:
    cargo fmt --check
    cargo clippy -- -D warnings
    cargo test

format:
    cargo fmt

lint:
    cargo clippy -- -D warnings

test:
    cargo test

build:
    cargo build --release

clean:
    cargo clean

outdated:
    cargo update --dry-run --verbose

update:
    cargo update --verbose

run *args:
    cargo run -- {{ args }}
