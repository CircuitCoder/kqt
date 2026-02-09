# Test Fixtures

This directory contains pre-generated test keys and certificates for the kqt integration tests.

## ⚠️ SECURITY WARNING ⚠️

**THESE KEYS ARE FOR TESTING ONLY!**

**DO NOT USE IN PRODUCTION!**

These keys are publicly available in the repository and provide **NO SECURITY**.

- These keys are committed to the public repository
- They are designed **ONLY** for automated testing
- Using these keys in production would be a severe security vulnerability
- These keys use the test suffix `test.local`

## Files

- `ca-private.txt` - CA private key (self-signed) **[TEST ONLY]**
- `ca-public.cert` - CA public certificate **[TEST ONLY]**
- `node1-private.txt` - Node 1 private key (signed by CA) **[TEST ONLY]**
- `node1-public.cert` - Node 1 public certificate **[TEST ONLY]**
- `node2-private.txt` - Node 2 private key (signed by CA) **[TEST ONLY]**
- `node2-public.cert` - Node 2 public certificate **[TEST ONLY]**

## Purpose

These pre-generated keys serve several purposes:
1. **CI Reproducibility**: Same keys every time ensures consistent test behavior
2. **Performance**: No key generation overhead during tests
3. **Simplicity**: Tests can run immediately without setup steps

All keys use the suffix `test.local` to clearly identify them as test keys.

## Important Notes

- All keys are in string format (not PEM)
- Keys are generated with the `test.local` suffix
- The CA is self-signed
- Node keys are signed by the test CA

## Regenerating Keys

If you need to regenerate the test keys (this should rarely be necessary):

```bash
cd rust/test/common
bash generate-keys.sh ../fixtures
```

This should only be needed if:
- The key format changes
- There's a specific security-related reason to rotate test keys
- You're testing key generation itself

After regenerating, commit the new keys to the repository.
