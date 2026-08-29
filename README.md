# DRP Protocol

DRP (Decentralized Rights Protocol) is a verification-oriented network protocol for requesting, evaluating, and independently validating claims about events, identities, activities, rights, and evidence.

## MVP

The first implementation establishes:

Claim → Evidence → Verification Request → Verifiers → Verification Result → Cryptographic Proof

The MVP is intentionally transport-agnostic at the protocol layer and uses HTTP as an initial gateway transport. It does not require specialized IoT hardware, does not put raw evidence on-chain, and does not treat AI output as ground truth.

## Repository layout

- `cmd/drpd` — DRP node daemon
- `internal/protocol` — canonical protocol objects and validation
- `internal/crypto` — signatures and hashing
- `internal/verification` — policy evaluation and verifier quorum
- `internal/network` — HTTP gateway and peer primitives
- `internal/store` — local durable MVP store
- `cmd/drp` — developer CLI
- `docs/protocol-spec.md` — normative protocol specification

## Run

```bash
go test ./...
go run ./cmd/drpd --addr :8080
```

Then:

```bash
curl http://localhost:8080/health
```

The protocol is experimental (v0.1) and not production-secure until audited.
