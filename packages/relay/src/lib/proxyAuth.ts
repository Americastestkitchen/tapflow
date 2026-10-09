import crypto from 'crypto'
import type http from 'http'
import { getDb } from '../db.js'
import { getAuth, sessionCookie } from '../middleware/auth.js'
import { normalizeEmail, EMAIL_KEY_SQL } from './email.js'
import type { TapflowConfig } from './config.js'
import { createLogger } from '@tapflowio/agent-core'

const logger = createLogger('relay:proxy-auth')

/**
 * Sign-in delegated to an authenticating reverse proxy, so a team that already puts the relay behind
 * SSO does not keep a second password per person.
 *
 * Only an AWS Application Load Balancer with an `authenticate-oidc` / `authenticate-cognito` action is
 * supported. The ALB signs the user's claims into `x-amzn-oidc-data` (ES256, key published per region
 * at `public-keys.auth.elb.<region>.amazonaws.com/<kid>`) and names itself in the header's `signer`.
 * **The signature and the signer are the whole trust decision**: anyone who can reach the relay
 * directly can send the header, so a plain-header scheme ("trust `X-Forwarded-User`") would make the
 * relay's network exposure its security boundary. Checking `signer` against the configured ALB ARN
 * stops a token another ALB in the same region minted from being replayed here.
 *
 * What it does on a request with no valid session cookie and a valid header: finds the user by email,
 * creating one with `defaultRole` (or Admin, for `adminEmails`) when there is none, and issues the
 * same session cookie a password sign-in does. Everything after that — roles, removal, the socket
 * revalidation — is the ordinary cookie path, unchanged. A created user has no password, so password
 * sign-in stays closed to them; the proxy is their only way in.
 */
// The shape is validated by the config schema (lib/config.ts), which is where each field is defined.
export type ProxyAuthConfig = NonNullable<TapflowConfig['proxyAuth']>
type AwsAlbProxyAuthConfig = Extract<ProxyAuthConfig, { provider: 'aws-alb' }>

export type KeyFetcher = (url: string) => Promise<string>

const HEADER = 'x-amzn-oidc-data'
// ALB key ids are UUIDs. Checked before the id goes into a URL, so a forged header cannot point the
// key fetch somewhere else.
const KID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-\d$/

const defaultFetcher: KeyFetcher = async (url) => {
  const res = await fetch(url, { signal: AbortSignal.timeout(5_000) })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.text()
}

// ALB encodes with base64url but keeps `=` padding, which strict JWT libraries reject; Buffer accepts both.
function decodeSegment(seg: string): Buffer {
  return Buffer.from(seg.replace(/=+$/, ''), 'base64url')
}

export interface AlbClaims {
  email: string
  name?: string
}

export class AlbTokenVerifier {
  // A key never changes under its kid, so the cache needs no expiry; a rotated key arrives as a new kid.
  private readonly keys = new Map<string, crypto.KeyObject>()

  constructor(
    private readonly cfg: AwsAlbProxyAuthConfig,
    private readonly fetchKey: KeyFetcher = defaultFetcher,
    private readonly now: () => number = () => Date.now(),
  ) {
    if (!REGION_RE.test(cfg.region)) throw new Error(`proxyAuth.region is not an AWS region: ${cfg.region}`)
  }

  /** The verified claims, or null with the reason logged at debug. Never throws on a bad token. */
  async verify(token: string): Promise<AlbClaims | null> {
    const parts = token.split('.')
    if (parts.length !== 3) return this.reject('not a JWT')
    let header: { alg?: unknown; kid?: unknown; signer?: unknown }
    let payload: { exp?: unknown; email?: unknown; name?: unknown }
    try {
      header = JSON.parse(decodeSegment(parts[0]).toString('utf8'))
      payload = JSON.parse(decodeSegment(parts[1]).toString('utf8'))
    } catch {
      return this.reject('undecodable')
    }
    if (header.alg !== 'ES256') return this.reject(`alg ${String(header.alg)}`)
    if (header.signer !== this.cfg.albArn) return this.reject(`signer ${String(header.signer)}`)
    if (typeof header.kid !== 'string' || !KID_RE.test(header.kid)) return this.reject('kid')

    const key = await this.keyFor(header.kid)
    if (!key) return null
    const ok = crypto.verify(
      'sha256',
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key, dsaEncoding: 'ieee-p1363' },
      decodeSegment(parts[2]),
    )
    if (!ok) return this.reject('signature')
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= this.now()) return this.reject('expired')
    if (typeof payload.email !== 'string' || !payload.email.includes('@')) return this.reject('no email')
    return { email: payload.email, name: typeof payload.name === 'string' ? payload.name : undefined }
  }

  private async keyFor(kid: string): Promise<crypto.KeyObject | null> {
    const cached = this.keys.get(kid)
    if (cached) return cached
    const url = `https://public-keys.auth.elb.${this.cfg.region}.amazonaws.com/${kid}`
    try {
      const key = crypto.createPublicKey(await this.fetchKey(url))
      this.keys.set(kid, key)
      return key
    } catch (err) {
      logger.warn(`could not load ALB public key ${url}: ${(err as Error).message}`)
      return null
    }
  }

  private reject(reason: string): null {
    logger.debug(`ignoring ${HEADER} (${reason})`)
    return null
  }
}

interface UserRow { id: number; email: string; role: string }

/** The member for this address, created on first sign-in. */
export function findOrCreateProxyUser(claims: AlbClaims, cfg: ProxyAuthConfig): UserRow {
  const db = getDb()
  const email = normalizeEmail(claims.email)
  const existing = db.prepare(`SELECT id, email, role FROM users WHERE ${EMAIL_KEY_SQL} = ? ORDER BY id LIMIT 1`)
    .get(email) as UserRow | undefined
  if (existing) return existing
  const isAdmin = cfg.adminEmails.some((a) => normalizeEmail(a) === email)
  const role = isAdmin ? 'Admin' : cfg.defaultRole
  const result = db.prepare('INSERT INTO users (email, role, password_hash, display_name) VALUES (?, ?, NULL, ?)')
    .run(email, role, claims.name ?? null)
  logger.info(`created ${role} ${email} on first sign-in`)
  return { id: Number(result.lastInsertRowid), email, role }
}

/** `cookieHeader` with its `tapflow_token` replaced by (or extended with) `token`. */
export function withSessionToken(cookieHeader: string | undefined, token: string): string {
  const others = (cookieHeader ?? '').split(/;\s*/).filter((c) => c !== '' && !c.startsWith('tapflow_token='))
  return [`tapflow_token=${token}`, ...others].join('; ')
}

/**
 * Signs the request in from the proxy's header when it has no valid session. On success it sets the
 * session cookie on the response **and** on `req`, so this very request — typically the dashboard's
 * first `auth/me` — is already authenticated instead of bouncing to the login page once.
 */
export async function applyProxyAuth(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  cfg: ProxyAuthConfig,
  verifier: AlbTokenVerifier,
): Promise<void> {
  const raw = req.headers[HEADER]
  if (typeof raw !== 'string' || raw === '') return
  if (getAuth(req)) return
  const claims = await verifier.verify(raw)
  if (!claims) return
  const user = findOrCreateProxyUser(claims, cfg)
  const cookie = sessionCookie({ userId: user.id, email: user.email, role: user.role })
  const token = cookie.slice('tapflow_token='.length, cookie.indexOf(';'))
  req.headers.cookie = withSessionToken(req.headers.cookie, token)
  res.setHeader('Set-Cookie', cookie)
}
