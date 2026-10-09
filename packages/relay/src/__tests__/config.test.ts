import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import path from 'path'

vi.mock('fs', () => ({
  default: {
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    writeFileSync: vi.fn(),
    chmodSync: vi.fn(),
  },
}))

describe('relay config validation', () => {
  let exitSpy: ReturnType<typeof vi.spyOn>
  let errorSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    vi.resetModules()
    vi.unstubAllEnvs()
    exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('process.exit') })
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('유효한 기본값 → 정상 로드', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.local.port).toBe(4000)
    expect(config.local.wsBackpressureBytes).toBe(1_048_576)
    // Exact, not a pattern: `/\.tapflow.data$/` matched both layouts and so guarded neither.
    expect(config.local.dataDir).toBe(path.join(process.env.TAPFLOW_HOME!, 'data'))
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('TAPFLOW_WS_BACKPRESSURE_BYTES=524288 → 적용됨', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.stubEnv('TAPFLOW_WS_BACKPRESSURE_BYTES', '524288')
    const { config } = await import('../lib/config.js')
    expect(config.local.wsBackpressureBytes).toBe(524288)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('TAPFLOW_WS_BACKPRESSURE_BYTES=0 → exit(1) (min 1 위반)', async () => {
    vi.stubEnv('TAPFLOW_WS_BACKPRESSURE_BYTES', '0')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('wsBackpressureBytes'))
  })

  it('TAPFLOW_PORT=abc → exit(1) + 에러 로그', async () => {
    vi.stubEnv('TAPFLOW_PORT', 'abc')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('local.port'))
  })

  it('tunnel port is unset by default', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.local.tunnelPort).toBeNull()
  })

  it('TAPFLOW_TUNNEL_PORT=4100 → applied', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.stubEnv('TAPFLOW_TUNNEL_PORT', '4100')
    const { config } = await import('../lib/config.js')
    expect(config.local.tunnelPort).toBe(4100)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('TAPFLOW_TUNNEL_PORT=abc → exit(1) naming the key', async () => {
    vi.stubEnv('TAPFLOW_TUNNEL_PORT', 'abc')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('local.tunnelPort'))
  })

  // 0 would ask for an ephemeral port, which nothing outside the process could be pointed at.
  it('TAPFLOW_TUNNEL_PORT=0 → exit(1)', async () => {
    vi.stubEnv('TAPFLOW_TUNNEL_PORT', '0')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  it('TAPFLOW_PORT=99999 → exit(1)', async () => {
    vi.stubEnv('TAPFLOW_PORT', '99999')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  it('JWT_SECRET 32자 미만 → exit(1) + 에러 로그', async () => {
    vi.stubEnv('JWT_SECRET', 'tooshort')
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('JWT_SECRET'))
  })

  it('JWT_SECRET 32자 이상 → 정상 로드', async () => {
    vi.stubEnv('JWT_SECRET', 'a'.repeat(32))
    const { getJwtSecret } = await import('../lib/config.js')
    expect(getJwtSecret()).toBe('a'.repeat(32))
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it('JWT_SECRET 미설정 시 per-install 시크릿을 자동 생성한다 (공개 dev 기본값 미사용)', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { getJwtSecret } = await import('../lib/config.js')
    const secret = getJwtSecret()
    expect(secret).not.toContain('tapflow-dev-secret')
    expect(secret.length).toBeGreaterThanOrEqual(32)
  })

  it('config 파일에 jwtSecret 잔존 시 deprecation 경고', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({ local: { jwtSecret: 'old-secret-value-from-config-file' } })
    )
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await import('../lib/config.js')
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('deprecated'))
  })

  it('tunnel 설정 없음 → config.tunnel은 null', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.tunnel).toBeNull()
  })

  it('config.json에 tunnel 섹션 → 파싱됨', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({
        tunnel: { provider: 'rathole', serverAddr: 'vps.example.com:2333', publicUrl: 'https://vps.example.com' },
      })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.tunnel).toMatchObject({ provider: 'rathole', serverAddr: 'vps.example.com:2333', publicUrl: 'https://vps.example.com', ssh: null })
  })

  it('tunnel.ssh 섹션 → 파싱됨', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({
        tunnel: {
          provider: 'rathole',
          serverAddr: 'vps.example.com:2333',
          publicUrl: 'https://vps.example.com',
          ssh: { host: 'vps.example.com', user: 'ubuntu', keyPath: '~/.ssh/id_rsa' },
        },
      })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    // `tunnel` is a union and only the rathole arm carries `ssh`; this block configures that arm.
    const tunnel = config.tunnel as Extract<typeof config.tunnel, { provider: 'rathole' }>
    expect(tunnel.ssh).toEqual({ host: 'vps.example.com', user: 'ubuntu', keyPath: '~/.ssh/id_rsa' })
  })

  it('tunnel.ssh.host 없음 → exit(1)', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({
        tunnel: {
          provider: 'rathole',
          serverAddr: 'vps.example.com:2333',
          publicUrl: 'https://vps.example.com',
          ssh: { host: '', user: 'ubuntu' },
        },
      })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  it('tunnel.provider tailscale → 파싱됨 (publicUrl 선택)', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({ tunnel: { provider: 'tailscale' } })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.tunnel).toMatchObject({ provider: 'tailscale' })
  })

  it('tunnel.provider tailscale + publicUrl → publicUrl 파싱됨', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({ tunnel: { provider: 'tailscale', publicUrl: 'http://my-mac.tailnet.ts.net:4000' } })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { config } = await import('../lib/config.js')
    expect(config.tunnel).toMatchObject({ provider: 'tailscale', publicUrl: 'http://my-mac.tailnet.ts.net:4000' })
  })

  it('tunnel.provider 미지원 값 → exit(1)', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({ tunnel: { provider: 'unknown', serverAddr: 'vps.example.com:2333', publicUrl: 'https://vps.example.com' } })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('tunnel.provider'))
  })

  it('tunnel.serverAddr 빈 문자열 → exit(1)', async () => {
    const fs = await import('fs')
    vi.mocked(fs.default.existsSync).mockReturnValue(true)
    vi.mocked(fs.default.readFileSync).mockReturnValue(
      JSON.stringify({ tunnel: { provider: 'rathole', serverAddr: '', publicUrl: 'https://vps.example.com' } })
    )
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
    expect(exitSpy).toHaveBeenCalledWith(1)
  })

  describe('agent.lean', () => {
    const withFile = async (body: unknown) => {
      const fs = await import('fs')
      vi.mocked(fs.default.existsSync).mockReturnValue(true)
      vi.mocked(fs.default.readFileSync).mockReturnValue(JSON.stringify(body))
    }

    it('is off when the file says nothing about it', async () => {
      await withFile({})
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      const { config } = await import('../lib/config.js')
      expect(config.agent.lean).toBe(false)
    })

    it('is read from the file', async () => {
      await withFile({ agent: { lean: true } })
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      const { config } = await import('../lib/config.js')
      expect(config.agent.lean).toBe(true)
    })

    it('TAPFLOW_LEAN overrides the file in both directions', async () => {
      await withFile({ agent: { lean: true } })
      vi.stubEnv('TAPFLOW_LEAN', 'off')
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      expect((await import('../lib/config.js')).config.agent.lean).toBe(false)

      vi.resetModules()
      await withFile({ agent: { lean: false } })
      vi.stubEnv('TAPFLOW_LEAN', 'on')
      expect((await import('../lib/config.js')).config.agent.lean).toBe(true)
    })

    it('an unrecognised TAPFLOW_LEAN is warned about and the file wins', async () => {
      await withFile({ agent: { lean: true } })
      vi.stubEnv('TAPFLOW_LEAN', 'yes')
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
      const { config } = await import('../lib/config.js')
      expect(config.agent.lean).toBe(true)
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('TAPFLOW_LEAN'))
    })

    it('a value that is not a boolean stops the load, naming the key', async () => {
      await withFile({ agent: { lean: 'yes' } })
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('agent.lean'))
    })
  })

  describe('proxyAuth', () => {
    const ALB = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/tapflow/abc123'
    const withFile = async (body: unknown) => {
      const fs = await import('fs')
      vi.mocked(fs.default.existsSync).mockReturnValue(true)
      vi.mocked(fs.default.readFileSync).mockReturnValue(JSON.stringify(body))
    }

    it('is off when the file says nothing about it', async () => {
      await withFile({})
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      expect((await import('../lib/config.js')).config.proxyAuth).toBeNull()
    })

    it('fills defaultRole and adminEmails when only the ALB is named', async () => {
      await withFile({ proxyAuth: { provider: 'aws-alb', albArn: ALB, region: 'us-east-1' } })
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      expect((await import('../lib/config.js')).config.proxyAuth).toEqual({
        provider: 'aws-alb', albArn: ALB, region: 'us-east-1', defaultRole: 'QA', adminEmails: [],
      })
    })

    it.each([
      ['an unknown provider', { provider: 'nginx', albArn: ALB, region: 'us-east-1' }, 'proxyAuth.provider'],
      ['a target group ARN', { provider: 'aws-alb', albArn: ALB.replace('loadbalancer/app', 'targetgroup'), region: 'us-east-1' }, 'proxyAuth.albArn'],
      ['a region that is not one', { provider: 'aws-alb', albArn: ALB, region: 'us-east-1/../x' }, 'proxyAuth.region'],
      ['an unknown role', { provider: 'aws-alb', albArn: ALB, region: 'us-east-1', defaultRole: 'Owner' }, 'proxyAuth.defaultRole'],
    ])('stops the load on %s, naming the key', async (_label, proxyAuth, key) => {
      await withFile({ proxyAuth })
      vi.spyOn(console, 'warn').mockImplementation(() => {})
      await expect(import('../lib/config.js')).rejects.toThrow('process.exit')
      expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining(key))
    })
  })
})
