import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { EventEmitter } from 'events'
import fs from 'fs'
import os from 'os'
import path from 'path'
import type http from 'http'
import { initDb, closeDb, getDb } from '../db.js'
import { signJwt } from '../middleware/auth.js'
import { handleListBuilds } from '../api/builds.js'

// Builds of one version often share a number (CI uploads per branch), so the search box has to find
// them by label too. Mutation: searching `version_name` alone fails the label row.

let tmpDir: string
beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tapflow-build-search-'))
  initDb(path.join(tmpDir, 'search.db'))
  const db = getDb()
  db.prepare("INSERT INTO users (id, email, role, password_hash) VALUES (1, 'a@example.com', 'Admin', 'x')").run()
  db.prepare("INSERT INTO apps (id, name, bundle_id_key, platform) VALUES (1, 'Coffee', 'com.a.coffee', 'ios')").run()
  const insert = db.prepare('INSERT INTO builds (app_id, version_name, build_number, bundle_id, file_path, version_label) VALUES (1, ?, ?, ?, ?, ?)')
  insert.run('6.17.0', '457', 'com.a.coffee', '/x/1', 'feature/search · PR 42')
  insert.run('6.17.0', '457', 'com.a.coffee', '/x/2', 'fix/payments · PR 43')
  insert.run('7.0.0', '1', 'com.a.coffee', '/x/3', null)
})
afterAll(() => {
  closeDb()
  fs.rmSync(tmpDir, { recursive: true })
})

function list(q: string): Promise<{ version_label: string | null; version_name: string }[]> {
  const req = new EventEmitter() as http.IncomingMessage
  req.method = 'GET'
  req.url = `/api/v1/builds?q=${encodeURIComponent(q)}`
  req.headers = { cookie: `tapflow_token=${signJwt({ userId: 1, email: 'a@example.com', role: 'Admin' })}` }
  return new Promise((resolve) => {
    const res = {
      writeHead: vi.fn(),
      setHeader: vi.fn(),
      end: (body: string) => resolve(JSON.parse(body).items),
    } as unknown as http.ServerResponse
    handleListBuilds(req, res)
  })
}

describe('build search', () => {
  it('matches the upload label', async () => {
    const items = await list('payments')
    expect(items.map((b) => b.version_label)).toEqual(['fix/payments · PR 43'])
  })

  it('still matches the version', async () => {
    const items = await list('7.0.0')
    expect(items.map((b) => b.version_name)).toEqual(['7.0.0'])
  })
})
