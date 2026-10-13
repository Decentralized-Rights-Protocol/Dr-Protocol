# DRP Protocol CLI

The npm-based command-line client for the Decentralized Rights Protocol (DRP). This is a lightweight Node.js client for the existing DRP Verification Network; it does not replace the Go node daemon or change consensus.

## Requirements

- Node.js 18.18 or newer
- A running DRP Verification Network for `status` and `verify`

## Run locally

From this directory:

```bash
node src/index.js --help
node src/index.js version
DRP_PROTOCOL_URL=http://localhost:8080 node src/index.js status
```

## Install from npm (after publication)

```bash
npm install --global drp-protocol-cli
drp --help
drp version
```

The package name is a proposed name and must be checked for availability before first publication.

## Configure the gateway

```bash
export DRP_PROTOCOL_URL=http://localhost:8080
drp status
```

Or pass `--url https://your-drp-gateway.example` to an individual command.

## Submit a verification request

Create a JSON file matching the DRP protocol request schema, then:

```bash
drp verify ./verification-request.json
```

This sends the JSON to `POST /drp/v1/verify`. It submits a request; it does not claim the activity is verified, and it does not itself anchor a transaction to a blockchain. Use a test gateway first and never put private/raw evidence in a request.

## Current scope

- `drp --help` and `drp version`
- `drp status` checks the gateway's `/health` endpoint
- `drp verify <request.json>` submits a protocol verification request

Planned next: inspect commands from the Go CLI, add schema-aware validation and structured errors, then add authenticated GitHub/MCP source verification and verified-proof lookup after those API contracts are stable.
