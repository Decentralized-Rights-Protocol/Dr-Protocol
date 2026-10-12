# DRP Protocol

DRP (Decentralized Rights Protocol) is a verification-oriented network protocol for requesting, evaluating, and independently validating claims about events, identities, activities, rights, and evidence.

## MVP

The first implementation establishes:

Claim → Evidence → Verification Request → Verifiers → Verification Result → Cryptographic Proof

The MVP is intentionally transport-agnostic at the protocol layer and uses HTTP as an initial gateway transport. It does not require specialized IoT hardware, does not put raw evidence on-chain, and does not treat AI output as ground truth.

## Repository layout

- `cmd/drpd` — DRP node daemon
- `internal/protocol` — versioned protocol objects and validation
- `internal/crypto` — Ed25519 signatures and hashing
- `internal/verification` — policy evaluation and verifier quorum
- `internal/network` — HTTP gateway and authenticated peer proof replication
- `internal/store` — in-memory test store and atomic JSON-backed node store
- `cmd/drp` — developer CLI
- `docs/protocol-spec.md` — protocol specification

## Run

Requires Go 1.23 or newer.

```bash
go test ./...
go run ./cmd/drpd --addr :8080 --data-dir ./data
```

The daemon creates `./data/store.json` for requests, proofs and attestations, and `./data/node-ed25519.key` for its stable Ed25519 node identity. Keep this directory on a persistent volume and back it up securely. Do not commit it or expose it publicly. The default data directory is local to one process; it is not blockchain consensus or a multi-node database.

Then:

```bash
curl http://localhost:8080/health
```

## Phase A cryptographic hardening\n\nThe current Phase A branch uses purpose-specific SHA-256 digest domains for claims, policies, and evidence, plus separate Ed25519 signature domains for proof objects and peer-replication envelopes. The node key loader also repairs existing key-file permissions to `0600`. New proofs declare the `ed25519-drp-proof-v1` signature scheme. The verifier retains a legacy path for existing proofs with no scheme field; unknown scheme identifiers are rejected. The Go JSON representation is currently deterministic for these structs, but cross-language canonical JSON interoperability remains future work.\n\n## Current limitations

The verifier registry and peer book are still in-memory and must be reconfigured after restart. Replication is authenticated HTTP proof exchange, not BFT consensus. The JSON store is intended as a single-process MVP backend; concurrent daemon processes must not share one data directory. The protocol is experimental (v0.1) and not production-secure until audited.
