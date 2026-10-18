# DRP Post-Quantum Security Prototype

## What this implements

This branch adds an experimental post-quantum digital-signature path using **ML-DSA-44**, the NIST FIPS 204 standardized signature algorithm, through Cloudflare's CIRCL Go library.

- Generate an ML-DSA-44 key pair and sign/verify exact message bytes using the `drp-pqc` local utility.
- Verify ML-DSA-44 signatures on DRP verifier attestations submitted to `POST /drp/v1/attestations`.
- Bind each verifier's registered `signatureAlgorithm` to the algorithm declared by each attestation.
- Preserve legacy Ed25519 attestations when `signatureAlgorithm` is omitted; omitted algorithms default to `Ed25519`.
- Reject unknown algorithms, malformed keys, modified messages/signatures, and attestation algorithms that do not match the verifier registry.
- Domain-separate ML-DSA signatures with `DRP-POAT-PROOF-v1`.

## Attestation integration

A registered verifier can advertise the algorithm and its public key in the verifier registration object:

```json
{
  "id": "verifier-pqc-1",
  "name": "PQC verifier",
  "publicKey": "<base64url-encoded ML-DSA-44 public key>",
  "signatureAlgorithm": "ML-DSA-44",
  "active": true
}
```

A signed attestation includes `"signatureAlgorithm": "ML-DSA-44"`. The signature is base64url-encoded without padding. To sign, serialize the attestation with `signature` set to an empty string, sign those exact JSON bytes with `internal/pqc.Sign`, then place the encoded signature in the envelope. Verification repeats that same serialization after clearing the signature field. The registered verifier's algorithm must match the attestation algorithm exactly.

Do not use hand-built JSON strings for signing. Build the typed protocol object and use Go's JSON serialization consistently; a future protocol version should define a versioned canonical encoding before cross-language signing is treated as interoperable.

## Test it

From the repository root:

```bash
go test ./internal/pqc ./internal/crypto ./internal/network ./cmd/drp-pqc
go test ./...
go build ./cmd/drpd
go build ./cmd/drp
go build ./cmd/drp-pqc
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
- ML-DSA is now wired into verifier-attestation signature validation, but the network's own generated `Proof` objects are still signed with the existing Ed25519 signer. This is an intentional first integration step; proof signing needs an explicit key lifecycle/configuration and migration design.
- This does not yet integrate ML-DSA into verifier identity issuance, wallets, consensus, blockchain transactions, or the Cosmos chain.
- ML-DSA is a digital-signature algorithm; it does not encrypt files or establish shared secrets. A separate standardized KEM such as ML-KEM is needed for key establishment/encryption workflows.
- The private key utility writes mode `0600` on POSIX systems, but filesystem permissions are not a substitute for secure key storage. Do not use it to protect production keys.
- CIRCL describes itself as an experimental cryptographic library and recommends caution for production use. Independent cryptographic review, interoperability tests, key lifecycle/revocation design, canonical serialization, and threat modelling are required before production use.

## Next integration phases

1. Define a versioned canonical DRP proof/attestation envelope and stable key identifiers.
2. Add configurable ML-DSA proof signing and verification, with explicit algorithm metadata and backwards-compatible Ed25519 handling.
3. Define verifier key registration, rotation, revocation, and recovery rules.
4. Benchmark signature sizes and verification costs for mobile devices, low-bandwidth nodes, and block storage.
5. Evaluate a hybrid migration strategy for existing classical signatures without pretending the old keys themselves become quantum-resistant.
