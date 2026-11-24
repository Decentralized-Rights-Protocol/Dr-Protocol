#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import process from 'node:process'

const VERSION = '0.2.0'
const DEFAULT_URL = 'http://127.0.0.1:8080'
const TIMEOUT_MS = 10_000

function help() {
  console.log(`DRP CLI v${VERSION}

Command-line client for the Decentralized Rights Protocol.

Usage:
  drp --help
  drp version
  drp status [--url <gateway-url>]
  drp validate <request.json>
  drp hash <file>
  drp verify <request.json> [--url <gateway-url>]
  drp proof <proof-id> [--url <gateway-url>]
  drp claim <request-id> [--url <gateway-url>]
  drp verifiers [--url <gateway-url>]
  drp peers [--url <gateway-url>]
  drp attestations [--claim-id <claim-id>] [--url <gateway-url>]

Options:
  --url <url>         DRP Verification Network base URL
  --claim-id <id>     Filter attestations by claim ID
  -h, --help          Show help
  -v, --version       Show version

Environment:
  DRP_PROTOCOL_URL    Default gateway URL (default: ${DEFAULT_URL})

Examples:
  drp hash ./evidence.pdf
  drp validate ./verification-request.json
  DRP_PROTOCOL_URL=http://localhost:8080 drp status
  drp verify ./verification-request.json --url http://localhost:8080
  drp proof request-123:proof

Safety:
  hash computes a local SHA-256 fingerprint; it does not upload the file.
  verify submits a request to the configured network. Use a test node first.
  A returned verification status is a network result, not a guarantee of truth.
`)
}

function optionValue(args, option) {
  const index = args.indexOf(option)
  if (index === -1) return undefined
  const value = args[index + 1]
  if (!value || value.startsWith('--')) throw new Error(`Expected a value after ${option}`)
  return value
}

function positional(args, usage) {
  const value = args[1]
  if (!value || value.startsWith('--')) throw new Error(`Usage: ${usage}`)
  return value
}

function baseUrl(args) {
  const raw = optionValue(args, '--url') ?? process.env.DRP_PROTOCOL_URL ?? DEFAULT_URL
  try {
    const url = new URL(raw)
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error()
    if (url.username || url.password) throw new Error()
    return url.toString().replace(/\/$/, '')
  } catch {
    throw new Error(`Invalid gateway URL: ${raw}`)
  }
}

async function requestJson(url, options = {}) {
  let response
  try {
    response = await fetch(url, {
      ...options,
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
  } catch (error) {
    throw new Error(`Could not reach DRP gateway at ${url}: ${error instanceof Error ? error.message : String(error)}`)
  }
  const text = await response.text()
  let payload
  try { payload = text ? JSON.parse(text) : null } catch { payload = text }
  if (!response.ok) {
    const detail = typeof payload === 'string' ? payload : JSON.stringify(payload)
    throw new Error(`DRP gateway returned HTTP ${response.status}: ${detail}`)
  }
  return payload
}

async function readRequest(path) {
  const raw = await readFile(path, 'utf8')
  let request
  try { request = JSON.parse(raw) } catch {
    throw new Error(`Invalid JSON in ${path}`)
  }
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error('Verification request must be a JSON object')
  }
  return request
}

// Mirrors the currently implemented Go VerificationRequest.Validate checks.
function validateRequest(request) {
  const claim = request.claim
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) {
    throw new Error('claim is required and must be an object')
  }
  for (const field of ['id', 'subject', 'type', 'statement']) {
    if (typeof claim[field] !== 'string' || claim[field].trim() === '') {
      throw new Error(`claim requires non-empty ${field}`)
    }
  }

  const policy = request.policy
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('policy is required and must be an object')
  }
  if (!Number.isInteger(policy.minVerifiers) || policy.minVerifiers < 1) {
    throw new Error('policy.minVerifiers must be an integer >= 1')
  }
  if (!Number.isInteger(policy.minEvidence) || policy.minEvidence < 1) {
    throw new Error('policy.minEvidence must be an integer >= 1')
  }
  if (!Array.isArray(request.evidence)) {
    throw new Error('evidence must be an array')
  }
  if (request.evidence.length < policy.minEvidence) {
    throw new Error(`insufficient evidence: policy requires ${policy.minEvidence}, received ${request.evidence.length}`)
  }
  return {
    valid: true,
    requestId: typeof request.id === 'string' && request.id ? request.id : null,
    claimId: claim.id,
    evidenceCount: request.evidence.length,
    minVerifiers: policy.minVerifiers,
    minEvidence: policy.minEvidence,
    note: 'Local structural checks passed. This does not verify evidence authenticity or contact the network.',
  }
}

async function main() {
  const args = process.argv.slice(2)
  const command = args[0]

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    help()
    return
  }
  if (command === '--version' || command === '-v' || command === 'version') {
    console.log(`DRP CLI v${VERSION}`)
    return
  }

  if (command === 'hash') {
    const filePath = positional(args, 'drp hash <file>')
    const bytes = await readFile(filePath)
    const digest = createHash('sha256').update(bytes).digest('hex')
    console.log(JSON.stringify({ algorithm: 'sha256', file: filePath, bytes: bytes.length, digest }, null, 2))
    return
  }

  if (command === 'validate') {
    const filePath = positional(args, 'drp validate <request.json>')
    const request = await readRequest(filePath)
    console.log(JSON.stringify(validateRequest(request), null, 2))
    return
  }

  if (command === 'status') {
    const url = baseUrl(args)
    const result = await requestJson(`${url}/health`)
    console.log(JSON.stringify({ gateway: url, status: 'reachable', response: result }, null, 2))
    return
  }

  if (command === 'verify') {
    const requestPath = positional(args, 'drp verify <request.json> [--url <gateway-url>]')
    const verificationRequest = await readRequest(requestPath)
    validateRequest(verificationRequest)
    const url = baseUrl(args)
    const result = await requestJson(`${url}/drp/v1/verify`, {
      method: 'POST',
      body: JSON.stringify(verificationRequest),
    })
    console.log(JSON.stringify({ gateway: url, submitted: true, result }, null, 2))
    return
  }

  if (command === 'proof' || command === 'claim') {
    const id = positional(args, `drp ${command} <id> [--url <gateway-url>]`)
    const url = baseUrl(args)
    const route = command === 'proof' ? 'proofs' : 'claims'
    const result = await requestJson(`${url}/drp/v1/${route}/${encodeURIComponent(id)}`)
    console.log(JSON.stringify({ gateway: url, resource: command, result }, null, 2))
    return
  }

  if (command === 'verifiers' || command === 'peers') {
    const url = baseUrl(args)
    const result = await requestJson(`${url}/drp/v1/${command}`)
    console.log(JSON.stringify({ gateway: url, resource: command, result }, null, 2))
    return
  }

  if (command === 'attestations') {
    const url = baseUrl(args)
    const claimId = optionValue(args, '--claim-id')
    const query = claimId ? `?claimId=${encodeURIComponent(claimId)}` : ''
    const result = await requestJson(`${url}/drp/v1/attestations${query}`)
    console.log(JSON.stringify({ gateway: url, resource: 'attestations', claimId: claimId ?? null, result }, null, 2))
    return
  }

  throw new Error(`Unknown command: ${command}. Run "drp --help" for usage.`)
}

main().catch((error) => {
  console.error(`drp: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
