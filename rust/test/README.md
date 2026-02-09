# KQT Integration Test Suite

This directory contains the modular integration test infrastructure for the kqt Rust implementation.

## Overview

The test infrastructure uses:
- **C test runner**: Dedicated test runner with PID and network namespace support
- **Embedded configuration keys**: Test keys are directly embedded in config files
- **Configuration files**: Each test suite has pre-configured TOML files
- **Test scripts**: Shell scripts that verify connectivity and behavior
- **Test runners**: Scripts to execute each test suite

## Architecture

The test runner (`test-runner.c`) provides:
- **PID Namespace Isolation**: Relaunches itself in a PID namespace
- **PR_SET_PDEATHSIG**: Ensures child processes are cleaned up when parent exits
- **Network Namespace Management**: Creates temporary network namespaces for each node
- **Automatic Cleanup**: All resources are properly cleaned up on exit

Each node runs in its own network namespace with its own veth interface, eliminating the need for different ports.

## Directory Structure

```
test/
├── test-runner.c          # C test runner (netns, PID namespace, cleanup)
├── Makefile               # Builds test-runner
├── l2/
│   ├── node1.toml        # L2 mode config for node1 (embedded keys)
│   ├── node2.toml        # L2 mode config for node2 (embedded keys)
│   ├── test-connectivity.sh  # L2 connectivity tests
│   └── run.sh            # L2 test suite runner
├── l3/
│   ├── node1.toml        # L3 mode config for node1 (embedded keys)
│   ├── node2.toml        # L3 mode config for node2 (embedded keys)
│   ├── test-connectivity.sh  # L3 connectivity tests
│   └── run.sh            # L3 test suite runner
├── l2-l3-incompatible/
│   ├── node1.toml        # L2 mode config (node1)
│   ├── node2.toml        # L3 mode config (node2)
│   ├── test-incompatibility.sh # L2-L3 incompatibility test
│   └── run.sh            # Incompatibility test runner
├── run-all.sh            # Run all test suites
└── README.md             # This file
```

## C Test Runner Features

The test runner (`test-runner.c`) is a dedicated C program that provides:

1. **PID Namespace Isolation**
   - Detects if not running as PID 1
   - Automatically relaunches itself in a PID namespace
   - Mounts /proc in the new namespace
   - All child processes are automatically cleaned up on exit

2. **PR_SET_PDEATHSIG**
   - Each child process uses PR_SET_PDEATHSIG
   - Ensures children are terminated if parent dies
   - Prevents orphaned processes

3. **Network Namespace Management**
   - Creates temporary network namespaces for each node
   - Automatically cleans up namespaces on exit
   - No persistent bindings (namespaces deleted after test)

4. **Veth Pair Creation**
   - Creates virtual ethernet pairs to connect namespaces
   - Configures IP addresses (10.0.0.1/24 and 10.0.0.2/24)
   - Each node in separate namespace (same port 9000 for both)

5. **Process Management**
   - Starts kqt nodes in their respective namespaces
   - Handles cleanup on any exit signal
   - Proper signal handling for graceful shutdown

## Test Configuration

All test configurations embed keys directly:
- No template substitution
- No key generation at runtime
- Keys are test-only and publicly available
- Each node uses same port (9000) since they're in different namespaces

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
- `gcc` for compiling the test runner
- Rust nightly toolchain (nightly-2026-01-18 or compatible)
- `ip` command from iproute2
- `/dev/net/tun` device for TUN/TAP support

## Running Tests

### Build the project first
```bash
cd rust
rustup default nightly-2026-01-18
cargo build --release
```

### Build the test runner
```bash
cd rust/test
make
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

- `KQT_BIN` - Path to kqt binary (default: `../../target/release/kqt`)

### Example: Custom binary path
```bash
export KQT_BIN=/path/to/kqt
sudo -E bash l2/run.sh
```

## Test Execution Flow

1. Runner script calls C test runner with config files and test script
2. C runner checks if PID 1, relaunches in PID namespace if not
3. Creates network namespaces and veth pairs
4. Starts kqt nodes in their respective namespaces
5. Executes test script in node1's namespace
6. Cleans up all resources on exit

## Known Limitations

Some container or sandbox environments may block UDP socket operations with "Operation not permitted" errors. The tests are designed to handle this gracefully and will report it as a limitation rather than a failure.
