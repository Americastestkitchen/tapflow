import { RelayServer, initDb, config, install, configFound, assertInstallDir, createCertProvider, startTlsBackgroundTasks, buildCorsOrigins, proxyWithoutPublicUrlWarning, resolveRelayDisplayHost, resolveTunnelPort, isInitialized } from '@tapflowio/relay'
import type { TunnelRuntime } from '@tapflowio/relay'
import { AgentRegistry } from '@tapflowio/agent-core'
import path from 'path'
import { requestAudioPermission, isAudioSupported } from '@tapflowio/ios-agent'
import '@tapflowio/android-agent'
import { banner, createSpinner, step, warn } from '../lib/print.js'
import { startConfiguredTunnel, tunnelRuntimeFor } from '../lib/tunnel-runner.js'
import { refuseUnlessBindable } from '../lib/port-available.js'
import type { TunnelPlugin } from '../lib/tunnel.js'

export interface StartOptions {
  device?: string
  platform?: string
}

const RELAY_PORT = config.local.port

export async function cmdStart(opts: StartOptions): Promise<void> {
  assertInstallDir()
  const explicit = opts.platform

  let platformsToRun: string[]
  if (!explicit || explicit === 'all') {
    platformsToRun = AgentRegistry.available()
  } else {
    if (!AgentRegistry.platforms().includes(explicit)) {
      banner('error', 'UNKNOWN PLATFORM', [
        `'${explicit}' is not a registered platform.`,
        `Registered: ${AgentRegistry.platforms().join(', ') || 'none'}`,
      ])
      process.exit(1)
    }
    platformsToRun = [explicit]
  }

  // Prime the audio-capture permission (audio is on by default) — shared by iOS capture and Android
  // host-mute (#341), both via the same signed helper / TCC grant. Non-blocking: if the grant already
  // exists the helper exits silently; otherwise the operator gets the one-time modal.
  if ((platformsToRun.includes('ios') || platformsToRun.includes('android')) &&
      process.env.TAPFLOW_AUDIO !== 'off' && isAudioSupported()) {
    requestAudioPermission(false)
  }

  // ── 1. Relay setup (always local) ─────────────────────────────────────────
  // The install dir, not the cwd: `start` from anywhere runs this machine's install.
  step(`Install dir  →  ${install.dir} (${install.reason})`)
  step(configFound ? `Config  →  ${install.configPath}` : 'Config  →  defaults (run tapflow init to configure)')
  step(`Data  →  ${config.local.dataDir}`)
  initDb(path.join(config.local.dataDir, 'tapflow.db'))

  // LAN HTTPS for the secure-context (Smooth/WebCodecs) path — same wiring as `tapflow relay start`.
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
  const agentConnectHost = tls && displayHost.toLowerCase() !== 'localhost' ? displayHost : '<this-ip>'
  // The co-located agent connects over localhost; the agent accepts the domain cert there (see isLocalhostWss).
  const relayUrl = `${wsScheme}://localhost:${RELAY_PORT}`

  // ── 2. Tunnel, before the relay listens (optional — a public URL for teammates) ──
  // The relay reads config, and config names a tunnel without saying whether it came up or at which
  // address: a Tailscale URL is detected here, not configured (#794). So the tunnel starts first and its
  // outcome goes to the relay, which uses it for invite links, dashboard links and CORS.
  // What that order costs: a rathole relay listens only once its VPS setup is done, and a relay that fails
  // to start leaves a tunnel to stop. The port is checked first because rathole's setupServer restarts the
  // VPS-side server, and a second start doomed to fail on the port would take the running one's tunnel down.
  // The tunnel listener opens with a tunnel, or on its own when its port is named for a tunnel tapflow does
  // not manage. The co-located agent below stays on the relay port, the one place loopback means local.
  let tunnel: TunnelPlugin | null = null
  let publicUrl: string | null = null
  let tunnelRuntime: TunnelRuntime | undefined
  let tunnelPort = config.local.tunnelPort ?? undefined
  if (config.tunnel) {
    const ports = { relayPort: RELAY_PORT, tunnelPort: resolveTunnelPort(config.local.tunnelPort, RELAY_PORT) }
    // `RelayServer`'s constructor refuses this too, but it is built after the tunnel — and rathole's
    // setupServer restarts the VPS-side server on its way, taking down the tunnel of whatever else that
    // VPS serves. A setting that cannot work is refused before anything is touched.
    if (ports.tunnelPort === RELAY_PORT) {
      throw new Error(`The tunnel port (${ports.tunnelPort}) must differ from the relay port. Set TAPFLOW_TUNNEL_PORT to another port.`)
    }
    tunnelPort = ports.tunnelPort
    await refuseUnlessBindable(RELAY_PORT, 'relay')
    await refuseUnlessBindable(ports.tunnelPort, 'tunnel', '127.0.0.1')
    const started = await startConfiguredTunnel(config.tunnel, ports)
    tunnel = started.tunnel
    tunnelRuntime = tunnelRuntimeFor(started.publicUrl, tls !== undefined)
    // The banner advertises only what the relay will hand out.
    publicUrl = tunnelRuntime.publicUrl
    if (started.publicUrl && !publicUrl) warn(`Not advertising ${started.publicUrl}: this relay serves HTTPS, and a plain-HTTP tunnel URL does not reach it.`)
  }

  // ── 3. Relay listens ──────────────────────────────────────────────────────
  const proxyWarning = proxyWithoutPublicUrlWarning(config, tunnelRuntime)
  if (proxyWarning) warn(proxyWarning)
  let server: RelayServer
  try {
    // Construction is inside the try too: a TLS key that does not match its cert throws here.
    server = new RelayServer({ port: RELAY_PORT, uploadsDir: path.join(config.local.dataDir, 'uploads'), wsBackpressureBytes: config.local.wsBackpressureBytes, trustedProxies: config.local.trustedProxies, corsOrigins: buildCorsOrigins(config, RELAY_PORT, tunnelRuntime), tls, tunnel: tunnelRuntime, tunnelPort, proxyAuth: config.proxyAuth })
    await server.start()
  } catch (err) {
    await tunnel?.stop()
    throw err
  }
  const stopTls = certProvider ? startTlsBackgroundTasks(certProvider, server, config.tls) : null
  step(`Relay started on ${httpScheme}://${displayHost}:${RELAY_PORT}`)
  if (tunnelPort !== undefined) step(`Tunnel clients connect to 127.0.0.1:${tunnelPort}`)
  // Setup is refused to anything arriving through the tunnel, so the public URL cannot be where it starts.
  const setupLines = publicUrl && !isInitialized()
    ? [`First run: create the admin account on this Mac — open ${httpScheme}://localhost:${RELAY_PORT} here, or run \`tapflow admin init\`.`]
    : []

  // ── 4. Agent availability check ───────────────────────────────────────────
  if (platformsToRun.length === 0) {
    banner('success', 'TAPFLOW RELAY READY', [
      `Relay  : ${httpScheme}://${displayHost}:${RELAY_PORT}`,
      ...(publicUrl ? [`Public : ${publicUrl}`] : []),
      ...setupLines,
      'No agent environment detected — running relay only.',
      `Connect a Mac agent:  tapflow agent start --relay ${wsScheme}://${agentConnectHost}:${RELAY_PORT} --token <agent-PAT>`,
      `  Issue an 'agent'-scope token in the dashboard (Settings → Tokens).`,
      'Press Ctrl+C to stop.',
    ])
    process.on('SIGINT', () => { stopTls?.(); void tunnel?.stop(); process.exit(0) })
    return
  }

  const agents: Array<{ disconnect(): void }> = []

  // ── 5. Connect each registered platform ──────────────────────────────────
  for (const platform of platformsToRun) {
    const spinner = createSpinner(`Connecting ${platform} agent…`)
    spinner.start()
    try {
      const agent = await AgentRegistry.connect(platform, relayUrl, { deviceFilter: opts.device, lean: config.agent.lean })
      spinner.stop(true)
      agents.push(agent)
    } catch (e) {
      spinner.stop(false)
      if (agents.length > 0) {
        console.log(`  ⚠  ${platform}: ${(e as Error).message}`)
      } else {
        banner('error', `${platform.toUpperCase()} CONNECTION FAILED`, [(e as Error).message])
        process.exit(1)
      }
    }
  }

  banner('success', 'TAPFLOW READY', [
    `Relay  : ${httpScheme}://${displayHost}:${RELAY_PORT}`,
    ...(publicUrl ? [`Public : ${publicUrl}`] : []),
    ...setupLines,
    `Open ${publicUrl ?? `${httpScheme}://${displayHost}:${RELAY_PORT}`} in your browser.`,
    'Press Ctrl+C to stop.',
  ])

  process.on('SIGINT', () => {
    stopTls?.()
    agents.forEach((a) => a.disconnect())
    void tunnel?.stop()
    process.exit(0)
  })
}
