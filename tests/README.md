# KQT Integration Tests

This directory contains integration tests for the kqt project.

## Test Scripts

- **generate-keys.sh** - Generates CA and node keypairs for testing
- **generate-configs.sh** - Generates TOML configuration files for test nodes
- **integration-test.sh** - Main integration test script that sets up network namespaces and runs connectivity tests

## Requirements

- Linux with network namespace support
- `sudo` access for creating network namespaces
- Rust nightly toolchain (nightly-2026-01-18 or compatible)
- `ip` command from iproute2

## Running Tests Locally

1. Build the project:
   ```bash
   cd rust
   cargo build --release
   ```

2. Run the integration test:
   ```bash
   cd tests
   sudo bash integration-test.sh
   ```

   The test will:
   - Generate CA and node certificates
   - Create two network namespaces with a bridge between them
   - Start kqt nodes in each namespace
   - Verify TUN/TAP device creation
   - Run connectivity tests (IPv4 and IPv6 pings with various packet sizes)
   - Clean up all resources

## Environment Variables

- `KQT_BIN` - Path to the kqt binary (default: `../rust/target/release/kqt`)
- `WORK_DIR` - Working directory for test files (default: `./run`)
- `NODE1_LISTEN_PORT` - Port for node1 (default: 9001)
- `NODE2_LISTEN_PORT` - Port for node2 (default: 9002)

## Test Logs

Test logs are saved to `$WORK_DIR/node1.log` and `$WORK_DIR/node2.log` (default: `./run/`).

## GitHub Actions

The integration test runs automatically in GitHub Actions on push and pull requests. See `.github/workflows/integration-test.yml`.
