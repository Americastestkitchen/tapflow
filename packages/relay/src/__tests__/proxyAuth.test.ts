import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import { EventEmitter } from 'events'
import crypto from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import type http from 'http'
import { initDb, closeDb, getDb } from '../db.js'
import { getAuth, signJwt } from '../middleware/auth.js'
import { AlbTokenVerifier, applyProxyAuth, findOrCreateProxyUser, withSessionToken } from '../lib/proxyAuth.js'
import type { ProxyAuthConfig } from '../lib/proxyAuth.js'

// Against a real database and real ES256 signatures: the ALB's token format is the contract, so a
// mocked verifier would pass whatever the test author believed the format to be.
//
// Mutations run against this file, each turning it red:
// - skipping the `signer` check → "a token signed by another ALB" fails.
// - skipping `crypto.verify` → "a tampered payload" fails.
// - dropping the `exp` check → "an expired token" fails.
// - not rewriting `req.headers.cookie` → "the same request is signed in" fails.
// - matching emails without normalizing → "an existing member, by any case" fails.

const ALB_ARN = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/tapflow/abc123'
const OTHER_ARN = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/other/def456'
const KID = '0f6c5e6e-1d1a-4b1e-9e0a-2b8f3a1c7d55'

const CFG: ProxyAuthConfig = {
  provider: 'aws-alb', albArn: ALB_ARN, region: 'us-east-1', defaultRole: 'QA', adminEmails: ['Boss@Example.com'],
}

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
const PEM = publicKey.export({ type: 'spki', format: 'pem' }).toString()

// ALB's own encoding: base64url, but with the `=` padding kept.
const seg = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url').padEnd(Math.ceil(JSON.stringify(o).length / 3) * 4, '=')

function albToken(over: { header?: object; payload?: object; key?: crypto.KeyObject } = {}): string {
  const header = seg({ alg: 'ES256', kid: KID, signer: ALB_ARN, iss: 'https://cognito', client: 'c', exp: 0, typ: 'JWT', ...over.header })
  const payload = seg({ sub: 's', email: 'alice@example.com', exp: Math.floor(Date.now() / 1000) + 60, iss: 'https://cognito', ...over.payload })
  const sig = crypto.sign('sha256', Buffer.from(`${header}.${payload}`), { key: over.key ?? privateKey, dsaEncoding: 'ieee-p1363' })
  return `${header}.${payload}.${sig.toString('base64url')}==`.replace(/==$/, sig.length % 3 === 1 ? '==' : sig.length % 3 === 2 ? '=' : '')
}

function makeVerifier() {
  const fetchKey = vi.fn(async (url: string) => {
    if (url !== `https://public-keys.auth.elb.us-east-1.amazonaws.com/${KID}`) throw new Error(`unexpected ${url}`)
    return PEM
  })
  return { verifier: new AlbTokenVerifier(CFG, fetchKey), fetchKey }
}

function makeReq(headers: Record<string, string> = {}): http.IncomingMessage {
  const em = new EventEmitter() as http.IncomingMessage
  em.headers = headers
  em.method = 'GET'
  return em
}

function makeRes() {
  const headers: Record<string, string> = {}
  return { setHeader: vi.fn((k: string, v: string) => { headers[k.toLowerCase()] = v }), _headers: headers } as unknown as
    http.ServerResponse & { _headers: Record<string, string> }
}

const userCount = () => (getDb().prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n

let tmpDir: string
beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tapflow-proxyauth-'))
  initDb(path.join(tmpDir, 'proxy.db'))
})
afterAll(() => {
  closeDb()
  fs.rmSync(tmpDir, { recursive: true })
})
beforeEach(() => {
  getDb().prepare('DELETE FROM users').run()
})

describe('AlbTokenVerifier', () => {
  it('accepts a token the configured ALB signed, padding and all', async () => {
    const { verifier } = makeVerifier()
    expect(await verifier.verify(albToken({ payload: { name: 'Alice' } }))).toEqual({ email: 'alice@example.com', name: 'Alice' })
  })

  it('refuses a token signed by another ALB', async () => {
    const { verifier } = makeVerifier()
    expect(await verifier.verify(albToken({ header: { signer: OTHER_ARN } }))).toBeNull()
  })

  it('refuses a tampered payload', async () => {
    const { verifier } = makeVerifier()
    const [h, , s] = albToken().split('.')
    const forged = `${h}.${seg({ email: 'mallory@example.com', exp: Math.floor(Date.now() / 1000) + 60 })}.${s}`
    expect(await verifier.verify(forged)).toBeNull()
  })

  it('refuses a token signed with a different key', async () => {
    const { verifier } = makeVerifier()
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
    expect(await verifier.verify(albToken({ key: other }))).toBeNull()
  })

  it('refuses an expired token', async () => {
    const { verifier } = makeVerifier()
    expect(await verifier.verify(albToken({ payload: { exp: Math.floor(Date.now() / 1000) - 1 } }))).toBeNull()
  })

  it('refuses a non-ES256 alg and a kid that is not a UUID, without fetching', async () => {
    const { verifier, fetchKey } = makeVerifier()
    expect(await verifier.verify(albToken({ header: { alg: 'none' } }))).toBeNull()
    expect(await verifier.verify(albToken({ header: { kid: '../../evil.example/key' } }))).toBeNull()
    expect(fetchKey).not.toHaveBeenCalled()
  })

  it('refuses garbage without throwing', async () => {
    const { verifier } = makeVerifier()
    expect(await verifier.verify('not-a-jwt')).toBeNull()
    expect(await verifier.verify('a.b.c')).toBeNull()
  })

  it('fetches each key once', async () => {
    const { verifier, fetchKey } = makeVerifier()
    await verifier.verify(albToken())
    await verifier.verify(albToken())
    expect(fetchKey).toHaveBeenCalledTimes(1)
  })

  it('answers null when the key endpoint fails', async () => {
    const verifier = new AlbTokenVerifier(CFG, async () => { throw new Error('offline') })
    expect(await verifier.verify(albToken())).toBeNull()
  })
})

describe('findOrCreateProxyUser', () => {
  it('creates a first-time user with the default role and no password', () => {
    const u = findOrCreateProxyUser({ email: 'Alice@Example.com', name: 'Alice' }, CFG)
    const row = getDb().prepare('SELECT email, role, password_hash, display_name FROM users WHERE id = ?').get(u.id)
    expect(row).toEqual({ email: 'alice@example.com', role: 'QA', password_hash: null, display_name: 'Alice' })
  })

  it('creates an adminEmails address as Admin', () => {
    expect(findOrCreateProxyUser({ email: 'boss@example.com' }, CFG).role).toBe('Admin')
  })

  it('finds an existing member, by any case, without changing their role', () => {
    getDb().prepare("INSERT INTO users (id, email, role, password_hash) VALUES (7, 'boss@example.com', 'Viewer', 'x')").run()
    const u = findOrCreateProxyUser({ email: 'BOSS@example.com' }, CFG)
    expect(u).toMatchObject({ id: 7, role: 'Viewer' })
    expect(userCount()).toBe(1)
  })
})

describe('withSessionToken', () => {
  it('replaces a stale tapflow_token and keeps the other cookies', () => {
    expect(withSessionToken('a=1; tapflow_token=old; b=2', 'new')).toBe('tapflow_token=new; a=1; b=2')
    expect(withSessionToken(undefined, 'new')).toBe('tapflow_token=new')
  })
})

describe('applyProxyAuth', () => {
  it('signs the same request in and sets the session cookie', async () => {
    const { verifier } = makeVerifier()
    const req = makeReq({ 'x-amzn-oidc-data': albToken(), cookie: 'tapflow_token=stale' })
    const res = makeRes()
    await applyProxyAuth(req, res, CFG, verifier)
    expect(getAuth(req)).toMatchObject({ email: 'alice@example.com', role: 'QA' })
    expect(res._headers['set-cookie']).toMatch(/^tapflow_token=[^;]+; HttpOnly; Path=\/; SameSite=Lax/)
  })

  it('leaves a request that already has a valid session alone', async () => {
    getDb().prepare("INSERT INTO users (id, email, role, password_hash) VALUES (3, 'carol@example.com', 'Developer', 'x')").run()
    const { verifier, fetchKey } = makeVerifier()
    const cookie = `tapflow_token=${signJwt({ userId: 3, email: 'carol@example.com', role: 'Developer' })}`
    const req = makeReq({ 'x-amzn-oidc-data': albToken(), cookie })
    const res = makeRes()
    await applyProxyAuth(req, res, CFG, verifier)
    expect(req.headers.cookie).toBe(cookie)
    expect(res.setHeader).not.toHaveBeenCalled()
    expect(fetchKey).not.toHaveBeenCalled()
  })

  it('does nothing for a forged header', async () => {
    const { verifier } = makeVerifier()
    const req = makeReq({ 'x-amzn-oidc-data': albToken({ header: { signer: OTHER_ARN } }) })
    const res = makeRes()
    await applyProxyAuth(req, res, CFG, verifier)
    expect(getAuth(req)).toBeNull()
    expect(res.setHeader).not.toHaveBeenCalled()
    expect(userCount()).toBe(0)
  })

  it('does nothing without the header', async () => {
    const { verifier } = makeVerifier()
    const req = makeReq()
    const res = makeRes()
    await applyProxyAuth(req, res, CFG, verifier)
    expect(res.setHeader).not.toHaveBeenCalled()
  })
})
