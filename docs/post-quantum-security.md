# DRP Post-Quantum Security Prototype

## What this implements

This branch adds a local, experimental post-quantum digital-signature primitive using **ML-DSA-44**, the NIST FIPS 204 standardized signature algorithm, via Cloudflare's CIRCL Go library.

- Generate a key pair.
- Sign the exact bytes of a file.
- Verify a signature against a public key and the exact message bytes.
- Reject tampered messages, tampered signatures, and signatures made with another key.
- Domain-separate signatures with the context string `DRP-POAT-PROOF-v1`.

## Test it

From the repository root:

```bash
go test ./internal/pqc ./cmd/drp-pqc
go test ./...
go run ./cmd/drp-pqc --help
```

Create a local proof fixture:

```bash
printf '{"protocol":"DRP","claimId":"claim-test-001","status":"VERIFIED"}\n' > /tmp/drp-proof.json
```

Generate a test key pair (the utility will not overwrite existing files):

```bash
go run ./cmd/drp-pqc keygen /tmp/drp-test-private.key /tmp/drp-test-public.key
```

Sign the fixture and verify it:

```bash
go run ./cmd/drp-pqc sign /tmp/drp-test-private.key /tmp/drp-proof.json /tmp/drp-proof.sig
go run ./cmd/drp-pqc verify /tmp/drp-test-public.key /tmp/drp-proof.json /tmp/drp-proof.sig
```

Expected final line:

```text
VALID: ML-DSA-44 signature verified
```

Test tamper detection:

```bash
printf '{"protocol":"DRP","claimId":"claim-test-001","status":"REVOKED"}\n' > /tmp/drp-proof-tampered.json
go run ./cmd/drp-pqc verify /tmp/drp-test-public.key /tmp/drp-proof-tampered.json /tmp/drp-proof.sig
```

The final command should fail with an invalid-signature result.

## Important security boundaries

- This is a **cryptographic prototype**, not a claim that the entire DRP network is quantum-secure.
- The primitive signs file bytes only. It is not yet wired into DRP attestations, verifier identities, API responses, wallets, consensus, or blockchain transactions.
- ML-DSA is a digital-signature algorithm; it does not encrypt files or establish shared secrets. A separate standardized KEM such as ML-KEM is needed for key establishment/encryption workflows.
- Sign a deterministic/canonical encoding of a proof object when integrating this into the protocol. JSON formatting changes otherwise change the signed bytes.
- The private key is written with filesystem mode 0600 on POSIX systems, but filesystem permissions are not a substitute for secure key storage. Do not use this utility to protect production keys.
- CIRCL describes itself as an experimental cryptographic library and recommends caution for production use. This code needs independent cryptographic review, interoperability tests, key lifecycle/revocation design, and threat modelling before production use.

## Next integration phase

1. Define a canonical DRP proof/attestation envelope and key identifiers.
2. Add ML-DSA verification to verifier attestation validation behind an explicit algorithm-version field.
3. Define key registration, rotation, revocation, and backward-compatibility rules.
4. Benchmark signature sizes and verification costs for mobile devices, low-bandwidth nodes, and block storage.
5. Evaluate a hybrid migration strategy for existing classical signatures without pretending the old keys themselves become quantum-resistant.
