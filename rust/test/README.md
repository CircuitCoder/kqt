# KQT Integration Test Suite

This directory contains the new modular integration test infrastructure for the kqt Rust implementation.

## Overview

The test infrastructure is organized into:
- **Configuration templates**: Stored in test-specific subdirectories (l2/, l3/, etc.)
- **Test driver**: Common infrastructure for network namespace setup and teardown
- **Test suites**: Individual test scripts for different scenarios
- **Test runners**: Scripts to execute each test suite

## Directory Structure

```
test/
├── common/
│   ├── generate-keys.sh      # Generate CA and node keypairs
│   └── test-driver.sh         # Core test driver (netns, veth, process mgmt)
├── l2/
│   ├── node1.toml            # L2 mode config template for node1
│   ├── node2.toml            # L2 mode config template for node2
│   ├── test-connectivity.sh  # L2 connectivity tests
│   └── run.sh                # L2 test suite runner
├── l3/
│   ├── node1.toml            # L3 mode config template for node1
│   ├── node2.toml            # L3 mode config template for node2
│   ├── test-connectivity.sh  # L3 connectivity tests
│   └── run.sh                # L3 test suite runner
├── l2-l3-incompatible/
│   ├── node1.toml            # L2 mode config (node1)
│   ├── node2.toml            # L3 mode config (node2)
│   ├── test-incompatibility.sh # L2-L3 incompatibility test
│   └── run.sh                # Incompatibility test runner
├── run-all.sh                # Run all test suites
└── README.md                 # This file
```

## Test Driver Features

The test driver (`common/test-driver.sh`) provides:

1. **PID Namespace Isolation**
   - Automatically launches in a PID namespace using `unshare --pid --fork --kill-child`
   - Runs as PID 1 within the namespace for proper process management
   - All child processes are automatically killed when the driver exits
   - Prevents resource leaks in network namespaces
   - Ensures reliable cleanup even on abnormal termination (SIGKILL, SIGTERM, etc.)

2. **Network Namespace Management**
   - Creates isolated network namespaces for each node
   - Automatically cleans up namespaces on exit
   - No persistent bindings (namespaces deleted after test)

3. **Veth Pair Creation**
   - Creates virtual ethernet pairs to connect namespaces
   - Configures IP addresses (10.0.0.1/24 and 10.0.0.2/24)
   - Brings up interfaces automatically

4. **Process Management**
   - Starts kqt nodes in their respective namespaces
   - Tracks process IDs for debugging
   - Handles cleanup on any exit signal (normal, interrupt, or error)
   - Child processes inherit proper signal handling from PID namespace

5. **Configuration Management**
   - Generates keys using common/generate-keys.sh
   - Replaces placeholders in config templates with actual keys
   - Creates working configs in run/ directory

## Test Suites

### L2 Connectivity Test
Tests L2 tunnel mode connectivity between two nodes.

**Tests:**
- TUN device creation
- IPv4 connectivity (default and large packets)
- IPv6 connectivity (default and large packets)

**Run:** `sudo bash l2/run.sh`

### L3 Connectivity Test
Tests L3 tunnel mode connectivity between two nodes.

**Tests:**
- TUN device creation
- IPv4 connectivity (default and large packets)
- IPv6 connectivity (default and large packets)

**Run:** `sudo bash l3/run.sh`

### L2-L3 Incompatibility Test
Tests that L2 and L3 tunnels cannot connect to each other.

**Tests:**
- Both nodes start successfully
- TUN devices are created
- Connection attempts fail (expected)
- Nodes remain running despite failed connections
- Connectivity does NOT work (expected behavior)

**Run:** `sudo bash l2-l3-incompatible/run.sh`

## Requirements

- Linux with network namespace support
- `sudo` access for creating network namespaces
- `unshare` command from util-linux (for PID namespace support)
- Rust nightly toolchain (nightly-2026-01-18 or compatible)
- `ip` command from iproute2
- `/dev/net/tun` device for TUN/TAP support
- **Important**: Full network namespace support with UDP socket permissions

## Running Tests

### Build the project first
```bash
cd rust
rustup default nightly-2026-01-18  # Or compatible nightly version
cargo build --release
```

### Run all test suites
```bash
cd rust/test
sudo bash run-all.sh
```

### Run individual test suite
```bash
cd rust/test
sudo bash l2/run.sh              # L2 connectivity
sudo bash l3/run.sh              # L3 connectivity
sudo bash l2-l3-incompatible/run.sh  # L2-L3 incompatibility
```

## Environment Variables

### Test Driver
- `WORK_DIR` - Working directory for configs and logs (default: `../run`)
- `KQT_BIN` - Path to kqt binary (default: `../../target/release/kqt`)
- `NS1`, `NS2` - Network namespace names (defaults: `kqt-test-ns1`, `kqt-test-ns2`)
- `VETH1`, `VETH2` - veth interface names (defaults: `veth1`, `veth2`)
- `NODE1_LISTEN_PORT` - Port for node1 (default: 9001)
- `NODE2_LISTEN_PORT` - Port for node2 (default: 9002)

### Example: Custom ports and namespaces
```bash
NODE1_LISTEN_PORT=10001 NODE2_LISTEN_PORT=10002 \
NS1=my-ns1 NS2=my-ns2 \
sudo bash l2/run.sh
```

## Configuration Templates

Configuration files in each test directory are templates with placeholders:
- `{CA_PUBLIC}` - CA public certificate
- `{NODE1_PRIVATE}` - Node 1 private key
- `{NODE2_PRIVATE}` - Node 2 private key
- `{NODE1_LISTEN_PORT}` - Node 1 listen port
- `{NODE2_LISTEN_PORT}` - Node 2 listen port

The test driver automatically replaces these placeholders when generating configs.

## Test Logs

Test logs are saved to `run/` directory:
- `run/node1.log` - Node 1 output
- `run/node2.log` - Node 2 output
- `run/node1.toml` - Generated node 1 config
- `run/node2.toml` - Generated node 2 config
- `run/*.txt`, `run/*.cert` - Generated keys and certificates

## Cleanup

The test driver automatically cleans up:
- Network namespaces (deleted on exit)
- veth interfaces (deleted with namespaces)
- kqt processes (terminated on exit)

Working directory (`run/`) is preserved for debugging but can be manually deleted:
```bash
rm -rf run/
```

## Adding New Tests

To add a new test suite:

1. Create a new directory under `test/`
2. Add config templates (node1.toml, node2.toml)
3. Create a test script (e.g., test-mytest.sh)
4. Create a runner script (run.sh) that calls test-driver.sh
5. Add to run-all.sh to include in full test suite

Example structure:
```
test/my-new-test/
├── node1.toml           # Config template
├── node2.toml           # Config template
├── test-mytest.sh       # Test script
└── run.sh               # Runner
```

## Known Limitations

Some container or sandbox environments may block UDP socket operations with "Operation not permitted" errors. The tests are designed to handle this gracefully and will report it as a limitation rather than a failure.

## Migration from Old Tests

The old test infrastructure in `tests/` directory has been replaced by this new modular infrastructure. Key improvements:

1. **Separated concerns**: Configuration templates separate from test logic
2. **Reusable driver**: Common test driver for all test suites
3. **Modular tests**: Easy to add new test scenarios
4. **Better cleanup**: Reliable process and namespace cleanup
5. **Better organization**: Clear directory structure for different test types
