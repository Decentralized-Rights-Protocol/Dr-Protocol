# DRP Verification Network Architecture

## North star

DRP is a verification-oriented protocol. HTTP is an initial transport/gateway, not the definition of the protocol.

Application → DRP client/SDK → DRP gateway → claim/evidence layer → verification engine → cryptographic proof → relying application.

## Network roles

- **Client** — creates claims and requests verification.
- **Gateway** — accepts protocol requests over HTTP initially.
- **Verifier** — independently evaluates evidence against a policy.
- **Peer** — propagates authenticated proof records over HTTP.
- **Archive/Indexer** — future role for durable public proof discovery.
- **Validator** — future blockchain role for state consensus.

## Two kinds of consensus

Blockchain consensus establishes agreement about network state.

Verification consensus establishes whether a claim satisfies a verification policy.

They MUST remain conceptually separate. A signature proves that a key signed bytes; it does not independently prove that the underlying real-world claim is true.

## Evidence and privacy

Evidence is represented by integrity/provenance metadata and content hashes. Sensitive raw evidence belongs off-chain by default. Public proof records should not require publishing personal documents or unnecessary identifying information.

## Proof

A DRP proof binds a claim digest, policy digest, evidence digests, verification result, and attestations. Proof and replication-envelope signatures are independently checkable with the appropriate public key.

## Current MVP boundary

v0.1 contains a working HTTP gateway, protocol objects, policy evaluation, proof generation/signing, and authenticated peer proof exchange. The daemon now has an atomic local JSON store for requests, proofs, and attestations, plus a stable local Ed25519 identity key. The verifier registry and peer book remain in-memory, so they must be reconfigured after a process restart. The local JSON file is single-process storage, not distributed consensus.

Durable peer/verifier configuration, multi-process crash/recovery testing, an independently deployed two-node test, public proof discovery, blockchain anchoring, selective disclosure, and production-grade Byzantine fault tolerance remain future milestones.
