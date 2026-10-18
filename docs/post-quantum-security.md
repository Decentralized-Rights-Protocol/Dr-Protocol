# DRP Post-Quantum Security Prototype

## What this implements

This branch adds an experimental post-quantum digital-signature path using **ML-DSA-44**, the NIST FIPS 204 standardized signature algorithm, through Cloudflare's CIRCL Go library.

- Generate an ML-DSA-44 key pair and sign/verify exact message bytes using the `drp-pqc` local utility.
- Verify ML-DSA-44 signatures on DRP verifier attestations submitted to `POST /drp/v1/attestations`.
- Bind each verifier's registered `signatureAlgorithm` to the algorithm declared by each attestation.
- Preserve legacy Ed25519 attestations when `signatureAlgorithm` is omitted; omitted algorithms default to `Ed25519`.
- Reject unknown algorithms, malformed keys, modified messages/signatures, non-canonical signature lengths, and attestation algorithms that do not match the verifier registry.
- Domain-separate ML-DSA signatures with `DRP-POAT-PROOF-v1`.
- Sign generated proof envelopes with either the compatibility Ed25519 signer or a configured ML-DSA-44 node signer.
- Include `signatureAlgorithm` and `signerId` in new proof envelopes and expose `GET /drp/v1/proofs/{proofId}/verify` for integrity verification against the node's configured signer.

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

## Configure persistent ML-DSA proof signing

The node defaults to an ephemeral Ed25519 key for local compatibility. That key changes on restart, so proofs signed with it will not verify after a restart. For persistent ML-DSA-44 proof signing, generate a key pair and protect the private key:

```bash
umask 077
go run ./cmd/drp-pqc keygen ./drp-node-private.key ./drp-node-public.key
chmod 600 ./drp-node-private.key
export DRP_NODE_ID=drp-node-1
export DRP_PQC_PRIVATE_KEY_FILE=./drp-node-private.key
export DRP_PQC_PUBLIC_KEY_FILE=./drp-node-public.key
go run ./cmd/drpd --addr :8080
```

Both key-file variables must be set together. The node rejects private-key files with group/other permissions and checks that the public/private key pair matches. Keep the private key out of source control and back it up securely.

Generated proofs include `signatureAlgorithm` and `signerId`. Verify a stored proof with:

```bash
curl http://127.0.0.1:8080/drp/v1/proofs/REQUEST_ID:proof/verify
```

The endpoint checks integrity against the currently configured signer. This is a node-local trust check, not a global public-key directory or consensus-level identity system; external clients still need an authenticated, independently trusted node public key. Only one proof signer is configured per node in this prototype.

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
- ML-DSA-44 can sign generated proof envelopes when explicitly configured. Ed25519 remains the default development fallback and uses an ephemeral key; do not use that fallback for durable production proofs.
- This does not yet integrate PQC into consensus, peer transport, wallets, or blockchain transactions. Node identity discovery, independently trusted public-key distribution, key rotation/revocation, and a production key-management service remain future work.
- The current JSON serialization approach is a prototype and should not be treated as a cross-language canonical signing format.
- Keep private keys out of source control and logs. Review the library's production-readiness guidance before deploying cryptography in production.
