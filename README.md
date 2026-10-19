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
- `internal/consensus` — experimental validator quorum, signed votes, commit certificates
- `internal/store/chain.go` — LevelDB-backed block and certificate persistence
- `internal/network` — HTTP gateway and peer primitives
- `internal/store` — local durable MVP store
- `cmd/drp` — developer CLI
- `docs/protocol-spec.md` — normative protocol specification

## Run

```bash
go test ./...
go run ./cmd/drpd --addr :8080 --chain-db ./data/drp-chain
```

Then:

```bash
curl http://localhost:8080/health
```

The protocol is experimental (v0.1) and not production-secure until audited.

## Experimental blockchain consensus

Consensus is opt-in and requires an explicit trusted validator set. Create a JSON
file mapping validator IDs to base64-encoded Ed25519 **public** keys:

```json
{
  "validator-a": "BASE64_ED25519_PUBLIC_KEY",
  "validator-b": "BASE64_ED25519_PUBLIC_KEY",
  "validator-c": "BASE64_ED25519_PUBLIC_KEY",
  "validator-d": "BASE64_ED25519_PUBLIC_KEY"
}
```

Start the node with:

```bash
go run ./cmd/drpd --addr :8080 --chain-db ./data/drp-chain --validators ./validators.json
```

The node validates the stored chain and its quorum certificates before restoring
the committed tip. Consensus endpoints are available under
`/drp/v1/consensus/`:

- `GET /status` — current height, hash, vote count, and quorum.
- `POST /proposals` — submit a block proposal.
- `POST /votes` — submit a signed validator vote.
- `POST /commit` — commit only after quorum and persist the block/certificate.

A proposal JSON body uses `height`, `previous_hash`, `timestamp_unix`, and
`payload` (base64-encoded bytes in JSON). Vote signatures are Ed25519 signatures
over the UTF-8 block-hash hex string. Keep validator private keys outside the
node and never put them in this public-key configuration file.

This is an experimental integration, not production BFT. It currently lacks
leader election, view changes, peer-to-peer consensus message propagation,
validator-set transitions, and full adversarial/network-partition testing.
The HTTP endpoints are not authenticated as an operator API; deploy only behind
a trusted boundary until authorization and transport security are implemented.
Ed25519 is not post-quantum secure. Do not use this prototype for real assets.
