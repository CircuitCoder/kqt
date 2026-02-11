# KQT Integration Tests

This directory contains integration tests for the kqt Rust implementation.

## Test Scripts

- **generate-keys.sh** - Generates CA and node keypairs for testing (string format only)
- **generate-configs.sh** - Generates TOML configuration files for test nodes. Takes optional MODE parameter (L2 or L3)
- **integration-test.sh** - Main integration test script that uses kqt-tester to set up network namespaces and run connectivity tests
- **worker-node0.sh** - Worker script for node 1 (runs inside network namespace, executes tests)
- **worker-node1.sh** - Worker script for node 2 (runs inside network namespace, server only)

## Architecture

The integration tests use the `kqt-tester` utility to create isolated network namespaces:
- `kqt-tester` creates two network namespaces with a veth pair connecting them
- Worker scripts run inside each namespace to start KQT nodes and execute tests
- The test infrastructure handles graceful degradation in sandbox environments

## Requirements

- Linux with network namespace support
- Rust nightly toolchain (nightly-2026-01-18 or compatible)
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
   cargo build --bin kqt --bin kqt-tester --release
   ```

2. Run the integration test:
   ```bash
   # From the rust directory
   cd tests
   
   # Generate keys and configs (L2 mode is the default)
   bash generate-keys.sh run
   bash generate-configs.sh run
   
   # Or for L3 mode
   bash generate-configs.sh run L3
   
   # Run tests (requires sudo for network namespace creation)
   sudo bash integration-test.sh
   ```

   The test will:
   - Use kqt-tester to create isolated network namespaces with veth pair
   - Start kqt nodes in each namespace via worker scripts
   - Verify TUN/TAP device creation
   - Run connectivity tests (IPv4 and IPv6 pings with various packet sizes)
   - Clean up automatically when worker scripts exit

## Environment Variables

- `KQT_BIN` - Path to the kqt binary (default: `../target/release/kqt`)
- `KQT_TESTER_BIN` - Path to the kqt-tester binary (default: `../target/release/kqt-tester`)
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
