import path from 'path'
import { initDb } from './db.js'
import { RelayServer } from './RelayServer.js'
import { config, loadedEnvPath, assertInstallDir } from './lib/config.js'
import { buildCorsOrigins, containerWithoutPublicUrlWarning, proxyWithoutPublicUrlWarning } from './lib/proxyConfig.js'
import { runningInContainer } from './lib/lanAddress.js'
import { bootstrapAdminFromEnv, AdminBootstrapError } from './lib/adminBootstrap.js'
import { createCertProvider, resolveRelayDisplayHost } from './lib/cert/index.js'
import { startTlsBackgroundTasks } from './lib/tlsTasks.js'
import { createLogger } from '@tapflowio/agent-core'

const logger = createLogger('relay')

assertInstallDir()

const { port, dataDir } = config.local
// config loaded <dataDir>/.env before reading any secret (JWT/SMTP/DNS tokens); just report it here.
if (loadedEnvPath) logger.info(`Loaded credentials from ${loadedEnvPath}`)
const dbPath = path.join(dataDir, 'tapflow.db')
const uploadsDir = path.join(dataDir, 'uploads')

initDb(dbPath)

// After the schema exists and before anything is served: a container cannot reach the HTTP
// bootstrap, because that one requires a local client and a container is always behind its bridge.
//
// **Fatal on failure.** The only way to get here with a problem is "an admin was asked for, there is
// none, and the settings are wrong" — serving that would leave the install ownerless and claimable
// from loopback. See `lib/adminBootstrap.ts`.
try {
  bootstrapAdminFromEnv(process.env, logger)
} catch (err) {
  // The reason is already logged where it was decided; re-logging it here printed every refusal
  // twice. Anything that is not a refusal has no message of its own yet, so that one is logged.
  if (!(err instanceof AdminBootstrapError)) logger.error(err instanceof Error ? err.message : String(err))
  process.exit(1)
}

// **The password does not outlive its use.** It is read once here, and every `spawnSync` in
// `api/builds.ts` — twelve of them, over user-uploaded archives — inherits `process.env` without
// passing one explicitly. Nothing reads these names again; `<dataDir>/.env` is re-read each boot.
delete process.env.TAPFLOW_ADMIN_PASSWORD
delete process.env.TAPFLOW_ADMIN_EMAIL

const corsOrigins = buildCorsOrigins(config, port)
const proxyWarning = proxyWithoutPublicUrlWarning(config)
if (proxyWarning) logger.warn(proxyWarning)
const containerWarning = containerWithoutPublicUrlWarning(config, runningInContainer())
if (containerWarning) logger.warn(containerWarning)

async function main(): Promise<void> {
  let tls: { cert: string; key: string } | undefined
  let provider: ReturnType<typeof createCertProvider> | null = null
  let displayHost = 'localhost'

  if (config.tls) {
    provider = createCertProvider(config.tls, { dataDir })
    const material = await provider.ensureCert()
    tls = { cert: material.cert, key: material.key }
    displayHost = resolveRelayDisplayHost(config.tls, material.cert, (message) => logger.warn(message))
  } else {
    logger.info(
      'TLS disabled — serving HTTP. Secure-context features (e.g. WebCodecs hardware decode) require HTTPS; ' +
      'configure tls in tapflow.config.json to enable.'
    )
  }

  // No `tunnel` option: this entry point starts no tunnel, so it has no runtime state to report and the
  // relay trusts config — an operator may run the tunnel alongside. See lib/publicUrl.ts.
  // The tunnel listener opens only when its port is named: it is loopback-only, so inside a container only
  // something sharing the relay's network namespace (a sidecar, host networking) could reach it at all.
  const server = new RelayServer({ port, uploadsDir, wsBackpressureBytes: config.local.wsBackpressureBytes, trustedProxies: config.local.trustedProxies, corsOrigins, tls, tunnelPort: config.local.tunnelPort ?? undefined, proxyAuth: config.proxyAuth })
  await server.start()
  logger.info(`tapflow relay running at ${tls ? 'https' : 'http'}://${displayHost}:${port}`)

  const stopTls = provider ? startTlsBackgroundTasks(provider, server, config.tls) : null

  const shutdown = () => {
    stopTls?.()
    void server.stop().then(() => process.exit(0))
  }
  process.on('SIGTERM', shutdown)
  process.on('SIGINT', shutdown)
}

void main().catch((err) => {
  logger.error(`relay failed to start: ${String(err)}`)
  process.exit(1)
})
