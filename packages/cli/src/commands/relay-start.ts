import path from 'path'
import { z } from 'zod'
import { RelayServer, initDb, config, loadedEnvPath, install, configFound, assertInstallDir, createCertProvider, startTlsBackgroundTasks, buildCorsOrigins, proxyWithoutPublicUrlWarning, resolveRelayDisplayHost, resolveTunnelPort, isInitialized } from '@tapflowio/relay'
import type { TunnelRuntime } from '@tapflowio/relay'
import { banner, step, warn } from '../lib/print.js'
import { startConfiguredTunnel, tunnelRuntimeFor } from '../lib/tunnel-runner.js'
import { refuseUnlessBindable } from '../lib/port-available.js'
import type { TunnelPlugin } from '../lib/tunnel.js'

export interface RelayStartOptions {
  port?: number
  tunnel?: string
}

const DEFAULT_PORT = config.local.port

const portSchema = z.number().int().min(1).max(65535, 'port must be between 1 and 65535')

const SUPPORTED_PROVIDERS = ['rathole', 'tailscale']

export async function cmdRelayStart(opts: RelayStartOptions): Promise<void> {
  assertInstallDir()
  const rawPort = opts.port ?? DEFAULT_PORT
  const portResult = portSchema.safeParse(rawPort)
  if (!portResult.success) {
    banner('error', 'INVALID CONFIG', [`--port: ${portResult.error.issues[0].message}`])
    process.exit(1)
  }
  const port = portResult.data

  // Tunnel settings are refused before anything starts, now that the tunnel comes up before the relay.
  if (opts.tunnel && !SUPPORTED_PROVIDERS.includes(opts.tunnel)) {
    banner('error', 'TUNNEL CONFIG ERROR', [`Unsupported tunnel provider: "${opts.tunnel}". Supported: ${SUPPORTED_PROVIDERS.join(', ')}`])
    process.exit(1)
  }
  const tunnelCfg = config.tunnel
  if (opts.tunnel && !tunnelCfg) {
    banner('error', 'TUNNEL CONFIG ERROR', ['tunnel section is required in tapflow.config.json when using --tunnel'])
    process.exit(1)
  }

  // The install dir, not the cwd: `start` from anywhere runs this machine's install.
  step(`Install dir  →  ${install.dir} (${install.reason})`)
  step(configFound ? `Config  →  ${install.configPath}` : 'Config  →  defaults (run tapflow init to configure)')
  step(`Data  →  ${config.local.dataDir}`)
  // config already loaded <dataDir>/.env before reading any secret (JWT/SMTP/DNS tokens); just report it.
  if (loadedEnvPath) step(`Loaded credentials from ${loadedEnvPath}`)
  initDb(path.join(config.local.dataDir, 'tapflow.db'))

  let tls: { cert: string; key: string } | undefined
  let certProvider: ReturnType<typeof createCertProvider> | null = null
  let displayHost = 'localhost'
  if (config.tls) {
    certProvider = createCertProvider(config.tls, { dataDir: config.local.dataDir })
    const material = await certProvider.ensureCert()
    tls = { cert: material.cert, key: material.key }
    displayHost = resolveRelayDisplayHost(config.tls, material.cert, warn)
  }
  const httpScheme = tls ? 'https' : 'http'
  const wsScheme = tls ? 'wss' : 'ws'
  const agentConnectHost = tls && displayHost.toLowerCase() !== 'localhost' ? displayHost : '<host>'

  // Tunnel before the relay, port checked first: same order and reasons as `tapflow start` (commands/start.ts).
  // The tunnel listener opens with a tunnel, or on its own when its port is named (see commands/start.ts).
  let tunnel: TunnelPlugin | null = null
  let publicUrl: string | null = null
  let tunnelRuntime: TunnelRuntime | undefined
  let tunnelPort = config.local.tunnelPort ?? undefined
  if (tunnelCfg != null) {
    const ports = { relayPort: port, tunnelPort: resolveTunnelPort(config.local.tunnelPort, port) }
    // `RelayServer`'s constructor refuses this too, but it is built after the tunnel — and rathole's
    // setupServer restarts the VPS-side server on its way, taking down the tunnel of whatever else that
    // VPS serves. A setting that cannot work is refused before anything is touched.
    if (ports.tunnelPort === port) {
      throw new Error(`The tunnel port (${ports.tunnelPort}) must differ from the relay port. Set TAPFLOW_TUNNEL_PORT to another port.`)
    }
    tunnelPort = ports.tunnelPort
    await refuseUnlessBindable(port, 'relay')
    await refuseUnlessBindable(ports.tunnelPort, 'tunnel', '127.0.0.1')
    const started = await startConfiguredTunnel(tunnelCfg, ports)
    tunnel = started.tunnel
    tunnelRuntime = tunnelRuntimeFor(started.publicUrl, tls !== undefined)
    // The banner advertises only what the relay will hand out.
    publicUrl = tunnelRuntime.publicUrl
    if (started.publicUrl && !publicUrl) warn(`Not advertising ${started.publicUrl}: this relay serves HTTPS, and a plain-HTTP tunnel URL does not reach it.`)
  }

  const proxyWarning = proxyWithoutPublicUrlWarning(config, tunnelRuntime)
  if (proxyWarning) warn(proxyWarning)
  let server: RelayServer
  try {
    // Construction is inside the try too: a TLS key that does not match its cert throws here.
    server = new RelayServer({ port, uploadsDir: path.join(config.local.dataDir, 'uploads'), wsBackpressureBytes: config.local.wsBackpressureBytes, trustedProxies: config.local.trustedProxies, corsOrigins: buildCorsOrigins(config, port, tunnelRuntime), tls, tunnel: tunnelRuntime, tunnelPort, proxyAuth: config.proxyAuth })
    await server.start()
  } catch (err) {
    await tunnel?.stop()
    throw err
  }
  step(`Relay started on ${httpScheme}://${displayHost}:${port}`)
  const stopTls = certProvider ? startTlsBackgroundTasks(certProvider, server, config.tls) : null

  banner('success', 'TAPFLOW RELAY READY', [
    `Relay  : ${httpScheme}://${displayHost}:${port}`,
    ...(publicUrl ? [`Public : ${publicUrl}`] : []),
    ...(tunnelPort !== undefined ? [`Tunnel : 127.0.0.1:${tunnelPort} (tunnel clients connect here)`] : []),
    // Setup is refused to anything arriving through the tunnel, so the public URL cannot be where it starts.
    ...(publicUrl && !isInitialized()
      ? [`First run: create the admin account on this machine — open ${httpScheme}://localhost:${port} here, or run \`tapflow admin init\`.`]
      : []),
    `Connect Mac agents:  tapflow agent start --relay ${wsScheme}://${agentConnectHost}:${port} --token <agent-PAT>`,
    `  Issue an 'agent'-scope token in the dashboard (Settings → Tokens).`,
    'Press Ctrl+C to stop.',
  ])

  process.on('SIGINT', () => {
    stopTls?.()
    void tunnel?.stop()
    process.exit(0)
  })
}
