# sign-invalid-secret-key

Malformed signing input vector for `provenact-cli sign`.

Expected behavior:
- `provenact-cli sign --bundle <dir> --signer alice.dev --secret-key invalid-secret-key.txt`
  fails with an invalid secret key parse error.
