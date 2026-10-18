# DRP Protocol CLI

The npm-based command-line client for the Decentralized Rights Protocol (DRP). This lightweight Node.js client talks to the existing DRP Verification Network; it does not replace the Go node daemon or change consensus.

## Requirements

- Node.js 18.18 or newer
- A running DRP Verification Network for network commands (status, verify, proof, claim, verifiers, peers, attestations)

## Run locally

From this directory:

    node src/index.js --help
    node src/index.js version
    npm test

## Install from npm

    npm install --global drp-protocol-cli@0.2.0
    drp --help
    drp version

If your shell already has an alias named drp, remove it for the current terminal with unalias drp. To find a persistent alias, search your shell config with:

    grep -n 'alias drp=' ~/.zshrc ~/.zprofile ~/.bash_profile ~/.bashrc 2>/dev/null

Remove the conflicting line from the file where it appears.

## Configure the gateway

    export DRP_PROTOCOL_URL=http://localhost:8080
    drp status

Or pass --url http://localhost:8080 to an individual network command.

## Offline tools

### Hash an evidence file

    drp hash ./evidence.pdf

Prints the file size and SHA-256 digest. The file stays local; the command does not upload it. A digest can help detect whether a file changed, but it does not prove who created the file or whether its contents are true.

### Validate a verification request

    drp validate ./verification-request.json

Checks the required claim fields, policy thresholds, and evidence count locally. The checks mirror the currently implemented Go request validation. This is a structural preflight, not evidence authentication or a guarantee that the gateway will accept the request.

Example request shape:

    {
      "version": "0.1",
      "id": "req-community-001",
      "claim": {
        "version": "0.1",
        "id": "claim-community-001",
        "subject": "did:drp:example",
        "type": "community_activity",
        "statement": "Participated in a community cleanup",
        "createdAt": "2026-10-18T12:00:00Z"
      },
      "evidence": [
        {
          "version": "0.1",
          "id": "evidence-001",
          "sourceId": "community-organizer",
          "type": "attestation",
          "contentHash": "replace-with-a-real-sha256-digest",
          "createdAt": "2026-10-18T12:00:00Z"
        }
      ],
      "policy": {
        "version": "0.1",
        "id": "policy-community-001",
        "minVerifiers": 2,
        "minEvidence": 1
      },
      "createdAt": "2026-10-18T12:00:00Z"
    }

Use a real timestamp and actual digest in your own request. Do not put private/raw evidence in a request.

## Network commands

    drp status
    drp verify ./verification-request.json
    drp proof req-community-001:proof
    drp claim req-community-001
    drp verifiers
    drp peers
    drp attestations
    drp attestations --claim-id claim-community-001

- status checks the gateway's /health endpoint.
- verify sends a request to POST /drp/v1/verify after local validation.
- proof <proof-id> fetches a proof by ID.
- claim <request-id> fetches the stored verification request by its request ID (the current API route is named claims).
- verifiers, peers, and attestations read the corresponding network endpoints.

A successful HTTP submission means the gateway accepted the request for processing. It does not independently establish truth, imply blockchain anchoring, or guarantee a VERIFIED result. Use a test node first.

## Test

    npm test
    npm pack --dry-run

The tests exercise the offline CLI commands. Network commands still require a reachable DRP gateway for end-to-end testing.
