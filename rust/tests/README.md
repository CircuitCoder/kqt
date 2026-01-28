# KQT Integration Tests

This directory contains integration tests for the kqt Rust implementation.

## Test Scripts

- **generate-keys.sh** - Generates CA and node keypairs for testing (string format only)
- **generate-configs.sh** - Generates TOML configuration files for test nodes
- **integration-test.sh** - Main integration test script that sets up network namespaces and runs connectivity tests

## Requirements

- Linux with network namespace support
- `sudo` access for creating network namespaces
- Rust nightly toolchain (nightly-2026-01-18 or compatible)
- `ip` command from iproute2
- **Important**: Full network namespace support with UDP socket permissions (may not work in restricted container/sandbox environments)

## Known Limitations

The integration tests require full network namespace support including the ability to send UDP packets with socket options like ECN (Explicit Congestion Notification). Some container or sandbox environments may block these operations with "Operation not permitted" errors. In such cases:
- The TUN device creation will succeed
- The nodes will start and listen on their ports
- But UDP packet transmission will fail with permission errors

If you encounter these limitations, you can still verify the build and basic functionality, but full integration tests will need to run on a system with unrestricted network namespace support.

## Running Tests Locally

1. Build the project:
   ```bash
   cd rust
   cargo build --release
   ```

2. Run the integration test:
   ```bash
   # From the rust directory
   cd tests
   sudo bash integration-test.sh
   ```

   The test will:
   - Generate CA and node certificates (string format, stored in .txt and .cert files)
   - Create two network namespaces with a direct veth pair connection
   - Start kqt nodes in each namespace
   - Verify TUN/TAP device creation
   - Run connectivity tests (IPv4 and IPv6 pings with various packet sizes)
   - Clean up all resources

## Environment Variables

- `KQT_BIN` - Path to the kqt binary (default: `../target/release/kqt`)
- `WORK_DIR` - Working directory for test files (default: `./run`)
- `NODE1_LISTEN_PORT` - Port for node1 (default: 9001)
- `NODE2_LISTEN_PORT` - Port for node2 (default: 9002)

## Test Logs

Test logs are saved to `$WORK_DIR/node1.log` and `$WORK_DIR/node2.log` (default: `./run/`).

## GitHub Actions

The integration test runs automatically in GitHub Actions on push and pull requests. See `.github/workflows/integration-test.yml`.

## Key Files Generated

The test generates the following files in string format (not PEM):
- `ca-private.txt` - CA private key
- `ca-public.cert` - CA public certificate
- `node1-private.txt` - Node 1 private key
- `node1-public.cert` - Node 1 public certificate
- `node2-private.txt` - Node 2 private key
- `node2-public.cert` - Node 2 public certificate
- `node1.toml` - Node 1 configuration
- `node2.toml` - Node 2 configuration
