import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const cli = fileURLToPath(new URL('../src/index.js', import.meta.url))
const tempDir = mkdtempSync(join(tmpdir(), 'drp-cli-test-'))

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' })
}

test('prints the CLI version', () => {
  const result = run('version')
  assert.equal(result.status, 0)
  assert.match(result.stdout, /DRP CLI v0\.2\.0/)
})

test('prints help with the new commands', () => {
  const result = run('--help')
  assert.equal(result.status, 0)
  assert.match(result.stdout, /drp hash <file>/)
  assert.match(result.stdout, /drp validate <request\.json>/)
  assert.match(result.stdout, /drp proof <proof-id>/)
})

test('hashes a file with SHA-256 without uploading it', () => {
  const file = join(tempDir, 'evidence.txt')
  writeFileSync(file, 'DRP evidence test')
  const result = run('hash', file)
  assert.equal(result.status, 0, result.stderr)
  const output = JSON.parse(result.stdout)
  assert.equal(output.algorithm, 'sha256')
  assert.equal(output.bytes, Buffer.byteLength('DRP evidence test'))
  assert.match(output.digest, /^[a-f0-9]{64}$/)
})

test('validates a structurally valid verification request offline', () => {
  const file = join(tempDir, 'valid.json')
  writeFileSync(file, JSON.stringify({
    version: '0.1',
    id: 'req-test-1',
    claim: { id: 'claim-test-1', subject: 'did:drp:test', type: 'community_activity', statement: 'Participated in a community cleanup' },
    evidence: [{ id: 'evidence-1', sourceId: 'local-test', type: 'document', contentHash: 'abc123' }],
    policy: { minVerifiers: 2, minEvidence: 1 },
  }))
  const result = run('validate', file)
  assert.equal(result.status, 0, result.stderr)
  const output = JSON.parse(result.stdout)
  assert.equal(output.valid, true)
  assert.equal(output.claimId, 'claim-test-1')
  assert.equal(output.evidenceCount, 1)
})

test('rejects a request that does not meet its evidence policy', () => {
  const file = join(tempDir, 'invalid.json')
  writeFileSync(file, JSON.stringify({
    claim: { id: 'claim-test-2', subject: 'did:drp:test', type: 'activity', statement: 'Test claim' },
    evidence: [],
    policy: { minVerifiers: 2, minEvidence: 1 },
  }))
  const result = run('validate', file)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /insufficient evidence/)
})

test('rejects malformed JSON with a useful error', () => {
  const file = join(tempDir, 'broken.json')
  writeFileSync(file, '{not json')
  const result = run('validate', file)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /Invalid JSON/)
})

test.after(() => {
  rmSync(tempDir, { recursive: true, force: true })
})
