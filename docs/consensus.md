# DRP blockchain consensus (experimental)

This package is the first blockchain-state consensus primitive and is separate
from the verification engine's policy/verifier quorum.

## Initial round flow

1. A node builds a canonical state-transition payload and proposes a block with
   the expected height and previous committed block hash.
2. Each validator checks the proposal and signs its SHA-256 block hash using
   its configured Ed25519 key.
3. The engine accepts one valid vote per registered validator.
4. Commit requires floor(2N/3)+1 distinct valid validator signatures. The
   returned certificate is independently checkable with VerifyCertificate.

The first block has height 1 and an empty parent hash. Subsequent blocks must
extend the last committed block. Payload bytes are hashed as part of the block
encoding; callers must use canonical payload encoding for deterministic hashes.

## Scope and safety limits

This is a testable quorum engine, NOT production-grade Byzantine Fault
Tolerant consensus. It currently has one pending proposal per engine and no
peer networking, leader election, rounds/view changes, timeout recovery,
persistent write-ahead log, validator-set transitions, slashing, or crash
recovery. The validator set is fixed at construction. Ed25519 is a classical
signature scheme, not post-quantum cryptography. Do not use this for real assets
or production network finality.

## Integration sequence

- Keep verification consensus (claim-policy decisions) distinct from block
  consensus (ordered network-state transitions).
- Next connect the engine to the node's durable store and peer layer, then expose
  proposal/vote/commit APIs, add persistence and restart/replay tests, and
  replace the fixed-set prototype with a reviewed BFT protocol.
- Post-quantum signing must be integrated through a versioned signature interface
  after algorithm and wire-format choices are reviewed; do not silently change
  the existing proof-signature format.
