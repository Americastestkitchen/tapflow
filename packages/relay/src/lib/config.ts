import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { z } from 'zod'
import { createLogger } from '@tapflowio/agent-core'
import { parseTrustedProxies } from './clientAddress.js'
import { dnsProviders } from './cert/dnsRegistry.js'
import { loadDataDirEnv } from './loadEnvFile.js'
import { resolveInstallDir, resolveDefaultDataDir, LEGACY_DATA_DIR, UNIFIED_DATA_DIR, type InstallDir } from './dataDir.js'
import { validateWebhookUrl } from './webhookUrl.js'

const logger = createLogger('relay:config')

const tunnelSshSchema = z.object({
  host: z.string().min(1),
  user: z.string().min(1),
  keyPath: z.string().optional(),
})

const ratholeTunnelSchema = z.object({
  provider: z.literal('rathole'),
  serverAddr: z.string().min(1),
  publicUrl: z.string().min(1),
  ssh: tunnelSshSchema.nullable(),
})

const tailscaleTunnelSchema = z.object({
  provider: z.literal('tailscale'),
  publicUrl: z.string().optional(),
})

const tunnelSchema = z.discriminatedUnion('provider', [ratholeTunnelSchema, tailscaleTunnelSchema])

// LAN HTTPS (issue #232) — secure context용 TLS 종단 설정. 골격: v1은 LAN 가지만 구현.
// 비밀(DNS API 토큰)은 config 파일이 아니라 env에서 읽는다(예: TAPFLOW_CLOUDFLARE_TOKEN).
const importCertTlsSchema = z.object({
  mode: z.literal('import-cert'),
  certPath: z.string().min(1),
  keyPath: z.string().min(1),
})

const byoApiTokenTlsSchema = z.object({
  mode: z.literal('byo-api-token'),
  domain: z.string().min(1),
  // 유효 provider는 레지스트리가 정한다(새 provider 추가 시 스키마 무변경).
  dnsProvider: z.string().min(1).refine((n) => dnsProviders.has(n), {
    message: `unknown dnsProvider (available: ${dnsProviders.names().join(', ')})`,
  }),
  // 도메인 A 레코드를 LAN IP로 자동 발행(기본 ON). false면 사용자가 직접 관리.
  publishAddress: z.boolean().optional(),
  // 자동 감지 대신 쓸 고정 LAN IP(멀티NIC/VPN 환경 오버라이드).
  address: z.string().min(1).optional(),
})

const tlsSchema = z.discriminatedUnion('mode', [byoApiTokenTlsSchema, importCertTlsSchema])

// Sign-in delegated to an authenticating reverse proxy (see lib/proxyAuth.ts). A discriminated union
// so another proxy can be added beside AWS ALB without changing this shape.
const proxyAuthSchema = z.discriminatedUnion('provider', [
  z.object({
    provider: z.literal('aws-alb'),
    albArn: z.string().regex(/^arn:aws[a-z-]*:elasticloadbalancing:[a-z0-9-]+:\d{12}:loadbalancer\/app\//, {
      message: 'must be an Application Load Balancer ARN',
    }),
    region: z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/, { message: 'must be an AWS region, e.g. us-east-1' }),
    defaultRole: z.enum(['Admin', 'Developer', 'QA', 'Viewer']),
    adminEmails: z.array(z.string()),
  }),
])

const configSchema = z.object({
  local: z.object({
    port: z.number().int().min(1).max(65535),
    dataDir: z.string().min(1),
    wsBackpressureBytes: z.number().int().min(1),
    trustedProxies: z.array(z.string()),
    // The loopback-only listener tunnel clients are pointed at (see RelayServer). null = not named.
    tunnelPort: z.number().int().min(1).max(65535).nullable(),
  }),
  relay: z.object({
    url: z.string().nullable(),
  }),
  tunnel: tunnelSchema.nullable(),
  tls: tlsSchema.nullable(),
  smtp: z.object({
    host: z.string(),
    port: z.number().int().min(1).max(65535),
    secure: z.boolean(),
    user: z.string(),
    pass: z.string(),
    from: z.string(),
  }),
  // Declarative outbound webhook endpoints. secret is resolved from an env var
  // (secretEnv in the file) — secrets never live in config.json.
  webhooks: z.array(
    z.object({
      url: z.string().min(1),
      secret: z.string(),
      enabled: z.boolean(),
    })
  ),
  // Read by this machine's agents, not by the relay: in a multi-Mac install each Mac's file decides
  // for its own agents (#851).
  agent: z.object({
    lean: z.boolean(),
  }),
  proxyAuth: proxyAuthSchema.nullable(),
})

export type TapflowConfig = z.infer<typeof configSchema>

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] }

const DEFAULTS = {
  local: {
    port: 4000,
    dataDir: '.tapflow/data',
    wsBackpressureBytes: 1_048_576,
    trustedProxies: [],
    tunnelPort: null,
  },
  relay: {
    url: null,
  },
  tunnel: null,
  tls: null,
  smtp: {
    host: '',
    port: 587,
    secure: false,
    user: '',
    pass: '',
    from: 'tapflow <noreply@tapflow.local>',
  },
  webhooks: [],
  agent: {
    lean: false,
  },
  proxyAuth: null,
} satisfies TapflowConfig

// TAPFLOW_DATA_DIR is a shell value, so a relative one means what it does in a shell: from the cwd.
function resolveFromCwd(raw: string): string {
  return path.isAbsolute(raw) ? raw : path.join(process.cwd(), raw)
}

// A path inside tapflow.config.json is relative to that file, the way tsconfig and litestream read
// theirs. It keeps `"dataDir": ".tapflow/data"` — what older `init` wrote and what
// `tapflow migrate data-dir` writes — pointing at the same directory it always did.
function resolveFromConfig(raw: string, configPath: string): string {
  return path.isAbsolute(raw) ? raw : path.join(path.dirname(configPath), raw)
}

const rawWebhookEntrySchema = z.array(
  z.object({
    url: z.string().optional(),
    secretEnv: z.string().optional(),
    enabled: z.boolean().optional(),
  })
)

// Map raw config.json webhook entries ({ url, secretEnv?, enabled? }) to resolved
// endpoints. The signing secret is read from the named env var, never from the file.
// Entries are dropped (with a warning) when they have no url or fail the SSRF/format
// gate, so config-file endpoints run under the same checks as REST-registered ones.
export function resolveWebhooksConfig(raw: unknown, env: NodeJS.ProcessEnv): TapflowConfig['webhooks'] {
  if (raw === undefined) return []
  const parsed = rawWebhookEntrySchema.safeParse(raw)
  if (!parsed.success) {
    logger.warn('webhooks in tapflow.config.json is malformed — ignoring')
    return []
  }
  const out: TapflowConfig['webhooks'] = []
  for (const w of parsed.data) {
    if (!w.url) continue
    const err = validateWebhookUrl(w.url)
    if (err) {
      logger.warn(`ignoring config webhook ${w.url}: ${err}`)
      continue
    }
    if (w.secretEnv && !env[w.secretEnv]) {
      logger.warn(`config webhook ${w.url}: secretEnv ${w.secretEnv} is not set — deliveries will be unsigned`)
    }
    out.push({
      url: w.url,
      secret: w.secretEnv ? (env[w.secretEnv] ?? '') : '',
      enabled: w.enabled !== false,
    })
  }
  return out
}

// Populated by load(): path of the dataDir/.env that was loaded, or null. CLI/server use it for a "loaded credentials" log.
export let loadedEnvPath: string | null = null

// Which install this process is running, decided once. `init` re-resolves at call time instead of
// reading this, because it can be pointed at another directory in the same process (its tests do).
export const install: InstallDir = resolveInstallDir()
// Whether the install's config file exists — the CLI's "not configured yet" hint reads this rather
// than looking in the cwd.
export let configFound = false
// Where local.dataDir came from, so `init` can pin the layout it found into a config it writes.
export let dataDirSource: 'env' | 'config' | 'existing' | 'default' = 'default'

/**
 * Refuse a `TAPFLOW_HOME` that names a directory nobody created. Commands that run or reach the
 * relay call this; `init` creates the directory instead. Deciding at import would take `setup`,
 * `doctor` and `init` down with it, because the CLI imports every command's module at startup.
 */
export function assertInstallDir(): void {
  if (!install.missing) return
  logger.error(`TAPFLOW_HOME is ${install.dir}, which does not exist. Create it, fix the variable, or run \`tapflow init\` to set it up.`)
  process.exit(1)
}

function load(): TapflowConfig {
  let file: DeepPartial<TapflowConfig> & { local?: { jwtSecret?: unknown } } = {}

  const configPath = install.configPath
  configFound = fs.existsSync(configPath)
  if (configFound) {
    try {
      file = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as typeof file
    } catch {
      logger.warn('Failed to parse tapflow.config.json — using defaults')
    }
  }

  if (file.local != null && 'jwtSecret' in file.local) {
    logger.warn('local.jwtSecret in tapflow.config.json is deprecated — use JWT_SECRET env var instead')
  }

  // Resolve dataDir first, then load <dataDir>/.env, so every secret read below (JWT_SECRET, SMTP,
  // DNS/ACME tokens) defaults to the .env file. dataDir itself can't come from .env (chicken-and-egg):
  // it's set only by config.json or TAPFLOW_DATA_DIR. Precedence: TAPFLOW_DATA_DIR > config.json > default.
  // The relay never moves data; when the default is in effect it resolves read-only, falling back to a
  // pre-existing legacy .tapflow-data/ so an un-migrated install keeps reading its data.
  let dataDir: string
  if (process.env.TAPFLOW_DATA_DIR) {
    dataDir = resolveFromCwd(process.env.TAPFLOW_DATA_DIR)
    dataDirSource = 'env'
  } else if (file.local?.dataDir != null) {
    dataDir = resolveFromConfig(file.local.dataDir, configPath)
    dataDirSource = 'config'
  } else {
    const resolved = resolveDefaultDataDir(install.dir, install.defaultDataLayout)
    dataDir = resolved.dataDir
    dataDirSource = resolved.existing ? 'existing' : 'default'
    if (resolved.usingLegacy) {
      logger.warn(`Reading data from the legacy ${LEGACY_DATA_DIR}/ — run \`tapflow migrate data-dir\` to move it into ${UNIFIED_DATA_DIR}/.`)
    }
  }
  for (const hidden of install.shadowed) {
    logger.warn(`Ignoring ${hidden}: this machine's install is ${install.dir}. Set TAPFLOW_HOME to use the other one.`)
  }
  loadedEnvPath = loadDataDirEnv(dataDir)

  const cfg: TapflowConfig = {
    local: {
      port: file.local?.port ?? DEFAULTS.local.port,
      dataDir,
      wsBackpressureBytes: DEFAULTS.local.wsBackpressureBytes,
      trustedProxies: parseTrustedProxies(process.env.TAPFLOW_TRUSTED_PROXIES),
      tunnelPort: file.local?.tunnelPort ?? DEFAULTS.local.tunnelPort,
    },
    relay: {
      url: file.relay?.url || null,
    },
    tunnel: (() => {
      if (file.tunnel == null) return null
      const t = file.tunnel as { provider?: string; serverAddr?: string; publicUrl?: string; ssh?: { host?: string; user?: string; keyPath?: string } | null }
      if (t.provider === 'tailscale') {
        return { provider: 'tailscale' as const, publicUrl: t.publicUrl }
      }
      // Pass the actual provider value so zod's discriminated union rejects unknown values
      return {
        provider: t.provider as 'rathole',
        serverAddr: t.serverAddr ?? '',
        publicUrl: t.publicUrl ?? '',
        ssh: t.ssh != null
          ? { host: t.ssh.host ?? '', user: t.ssh.user ?? '', keyPath: t.ssh.keyPath }
          : null,
      }
    })(),
    tls: (() => {
      if (file.tls == null) return null
      const t = file.tls as {
        mode?: string; certPath?: string; keyPath?: string; domain?: string; dnsProvider?: string
        publishAddress?: boolean; address?: string
      }
      if (t.mode === 'import-cert') {
        return {
          mode: 'import-cert' as const,
          certPath: t.certPath ? resolveFromConfig(t.certPath, configPath) : '',
          keyPath: t.keyPath ? resolveFromConfig(t.keyPath, configPath) : '',
        }
      }
      // Pass mode/provider through (no silent default) so zod rejects a missing/misspelled provider.
      return {
        mode: t.mode as 'byo-api-token',
        domain: t.domain ?? '',
        dnsProvider: t.dnsProvider ?? '',
        ...(t.publishAddress !== undefined ? { publishAddress: t.publishAddress } : {}),
        ...(t.address !== undefined ? { address: t.address } : {}),
      }
    })(),
    smtp: {
      host: file.smtp?.host ?? DEFAULTS.smtp.host,
      port: file.smtp?.port ?? DEFAULTS.smtp.port,
      secure: file.smtp?.secure ?? DEFAULTS.smtp.secure,
      user: file.smtp?.user ?? DEFAULTS.smtp.user,
      pass: file.smtp?.pass ?? DEFAULTS.smtp.pass,
      from: file.smtp?.from ?? DEFAULTS.smtp.from,
    },
    webhooks: resolveWebhooksConfig((file as { webhooks?: unknown }).webhooks, process.env),
    agent: {
      lean: file.agent?.lean ?? DEFAULTS.agent.lean,
    },
    proxyAuth: (() => {
      if (file.proxyAuth == null) return null
      const p = file.proxyAuth as { provider?: string; albArn?: string; region?: string; defaultRole?: string; adminEmails?: string[] }
      // Pass the provider through (no silent default) so zod rejects a missing/misspelled one.
      return {
        provider: p.provider as 'aws-alb',
        albArn: p.albArn ?? '',
        region: p.region ?? '',
        defaultRole: (p.defaultRole ?? 'QA') as 'QA',
        adminEmails: p.adminEmails ?? [],
      }
    })(),
  }

  if (process.env.TAPFLOW_PORT) cfg.local.port = Number(process.env.TAPFLOW_PORT)
  if (process.env.TAPFLOW_TUNNEL_PORT) cfg.local.tunnelPort = Number(process.env.TAPFLOW_TUNNEL_PORT)
  // TAPFLOW_DATA_DIR is already applied above (before the .env load) — it can't be set from .env.
  if (process.env.TAPFLOW_WS_BACKPRESSURE_BYTES) cfg.local.wsBackpressureBytes = Number(process.env.TAPFLOW_WS_BACKPRESSURE_BYTES)
  if (process.env.TAPFLOW_RELAY_URL) cfg.relay.url = process.env.TAPFLOW_RELAY_URL || null
  if (process.env.SMTP_HOST) cfg.smtp.host = process.env.SMTP_HOST
  if (process.env.SMTP_PORT) cfg.smtp.port = Number(process.env.SMTP_PORT)
  if (process.env.SMTP_SECURE) cfg.smtp.secure = process.env.SMTP_SECURE === 'true'
  if (process.env.SMTP_USER) cfg.smtp.user = process.env.SMTP_USER
  if (process.env.SMTP_PASS) cfg.smtp.pass = process.env.SMTP_PASS
  if (process.env.SMTP_FROM) cfg.smtp.from = process.env.SMTP_FROM
  const lean = process.env.TAPFLOW_LEAN
  if (lean === 'on' || lean === 'off') cfg.agent.lean = lean === 'on'
  else if (lean) logger.warn(`TAPFLOW_LEAN=${lean} is not on or off — using agent.lean from the config file`)

  // auto-derive from address when user is set but from was never explicitly configured
  if (cfg.smtp.user && file.smtp?.from === undefined && process.env.SMTP_FROM === undefined) {
    cfg.smtp.from = `tapflow <${cfg.smtp.user}>`
  }

  const result = configSchema.safeParse(cfg)
  if (!result.success) {
    for (const issue of result.error.issues) {
      logger.error(`config error: ${issue.path.join('.')} — ${issue.message}`)
    }
    process.exit(1)
  }

  return result.data
}

// JWT_SECRET 미설정 시: 공개된 공유 기본값 대신 per-install 시크릿을 생성·영속화한다.
// dataDir에 0600으로 저장하고 재시작 시 재사용 → 설정 없이도 위조 불가, 온보딩 friction 없음.
export function loadOrCreatePersistedSecret(dataDir: string): string {
  const secretPath = path.join(dataDir, 'jwt-secret')
  try {
    const existing = fs.readFileSync(secretPath, 'utf-8').trim()
    if (existing.length >= 32) return existing
  } catch {
    // not yet created
  }
  const secret = crypto.randomBytes(48).toString('base64url')
  fs.mkdirSync(dataDir, { recursive: true })
  fs.writeFileSync(secretPath, secret, { mode: 0o600 })
  try {
    fs.chmodSync(secretPath, 0o600)
  } catch {
    // best-effort on platforms without POSIX permissions
  }
  logger.info(`Generated a per-install JWT secret at ${secretPath} (set JWT_SECRET to override)`)
  return secret
}

// Checked at import, where a bad value belongs: it reads the environment and writes nothing.
function checkJwtSecretEnv(): void {
  if (process.env.JWT_SECRET !== undefined && process.env.JWT_SECRET.length < 32) {
    logger.error('config error: JWT_SECRET — must be at least 32 characters')
    process.exit(1)
  }
}

let cachedJwtSecret: string | null = null

/**
 * The secret this install signs with, created on first use rather than at import.
 *
 * Creating it at import meant **every** CLI command wrote one wherever it ran — `tapflow --version`
 * in a repo left a `.tapflow/data/jwt-secret` behind, an agent-only Mac and a CI runner got one for
 * a relay they never start. `RelayServer.start()` calls this on boot, so the file and its log still
 * appear when a relay comes up, and a write failure is still a boot failure rather than a 500 at
 * the first sign-in.
 */
export function getJwtSecret(): string {
  cachedJwtSecret ??= process.env.JWT_SECRET ?? loadOrCreatePersistedSecret(config.local.dataDir)
  return cachedJwtSecret
}

export const config = load()
checkJwtSecretEnv()
