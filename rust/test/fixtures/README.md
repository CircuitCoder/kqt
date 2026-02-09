# Test Fixtures

This directory contains pre-generated test keys and certificates for the kqt integration tests.

## Files

- `ca-private.txt` - CA private key (self-signed)
- `ca-public.cert` - CA public certificate
- `node1-private.txt` - Node 1 private key (signed by CA)
- `node1-public.cert` - Node 1 public certificate
- `node2-private.txt` - Node 2 private key (signed by CA)
- `node2-public.cert` - Node 2 public certificate

## Important Notes

**These keys are for testing purposes only!**

- All keys use the suffix `test.local`
- These are **NOT** production keys
- These keys are committed to the repository for CI reproducibility
- Never use these keys for anything other than automated testing

## Regenerating Keys

If you need to regenerate the test keys:

```bash
cd rust/test/common
bash generate-keys.sh ../fixtures
```

This should only be needed if the key format changes or if there's a specific reason to update the test keys.
