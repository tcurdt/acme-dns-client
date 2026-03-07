# Release Process

### 1. Bump the version

Update the version in `Cargo.toml`:

```toml
[package]
version = "0.2.0"  # Update this
```

### 2. Check dependencies (optional)

```bash
just outdated
just update
```

### 3. Run all checks

Ensure everything passes before releasing:

```bash
just check
just build
```

This runs formatting, linting, tests, and builds.

### 4. Update CHANGELOG.md

Add an entry for the new version with changes since the last release.

### 5. Commit version bump

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Bump version to 0.2.0"
```

### 6. Tag and push

```bash
# create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0"
# push commits and tags
git push && git push --tags
```

### 7. Automation

The GitHub Actions workflow will automatically:

- Update the Homebrew formula in `tcurdt/homebrew-tap`
- Users can install via `brew install tcurdt/tap/acme-dns-client`

### 8. Verify

After the workflow completes:

- Check that the Homebrew formula was updated
- Test installation: `brew install tcurdt/tap/acme-dns-client`
- Test Nix: `nix run github:tcurdt/acme-dns-client -- --version`
