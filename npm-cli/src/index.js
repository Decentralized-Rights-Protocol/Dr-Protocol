#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import process from 'node:process'

const VERSION = '0.1.0'
const DEFAULT_URL = 'http://127.0.0.1:8080'

function help() {
  console.log(`DRP CLI v${VERSION}

Command-line client for the Decentralized Rights Protocol.

Usage:
  drp --help
  drp version
  drp status [--url <gateway-url>]
  drp verify <request.json> [--url <gateway-url>]

Options:
  --url <url>   DRP Verification Network base URL
  -h, --help    Show help
  -v, --version Show version

Environment:
  DRP_PROTOCOL_URL   Default gateway URL (default: ${DEFAULT_URL})

Examples:
  DRP_PROTOCOL_URL=http://localhost:8080 drp status
  drp verify ./verification-request.json --url http://localhost:8080

Note: verify submits a request to the configured network. Use a test node first.
`)
}

function optionValue(args, option) {
  const index = args.indexOf(option)
  if (index === -1) return undefined
  const value = args[index + 1]
  if (!value || value.startsWith('--')) throw new Error(`Expected a value after ${option}`)
  return value
}

function baseUrl(args) {
  const raw = optionValue(args, '--url') ?? process.env.DRP_PROTOCOL_URL ?? DEFAULT_URL
  try {
    const url = new URL(raw)
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error()
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
      signal: AbortSignal.timeout(10_000),
    })
  } catch (error) {
    throw new Error(`Could not reach DRP gateway at ${url}: ${error instanceof Error ? error.message : String(error)}`)
  }
  const text = await response.text()
  let payload
  try { payload = text ? JSON.parse(text) : null } catch { payload = text }
  if (!response.ok) {
    throw new Error(`DRP gateway returned HTTP ${response.status}: ${typeof payload === 'string' ? payload : JSON.stringify(payload)}`)
  }
  return payload
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

  if (command === 'status') {
    const url = baseUrl(args)
    const result = await requestJson(`${url}/health`)
    console.log(JSON.stringify({ gateway: url, status: 'reachable', response: result }, null, 2))
    return
  }

  if (command === 'verify') {
    const requestPath = args[1]
    if (!requestPath || requestPath.startsWith('--')) {
      throw new Error('Usage: drp verify <request.json> [--url <gateway-url>]')
    }
    const raw = await readFile(requestPath, 'utf8')
    let verificationRequest
    try { verificationRequest = JSON.parse(raw) } catch {
      throw new Error(`Invalid JSON in ${requestPath}`)
    }
    if (!verificationRequest || typeof verificationRequest !== 'object' || Array.isArray(verificationRequest)) {
      throw new Error('Verification request must be a JSON object')
    }
    const url = baseUrl(args)
    const result = await requestJson(`${url}/drp/v1/verify`, {
      method: 'POST',
      body: JSON.stringify(verificationRequest),
    })
    console.log(JSON.stringify({ gateway: url, submitted: true, result }, null, 2))
    return
  }

  throw new Error(`Unknown command: ${command}. Run "drp --help" for usage.`)
}

main().catch((error) => {
  console.error(`drp: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
