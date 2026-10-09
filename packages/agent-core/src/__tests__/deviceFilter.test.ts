import { describe, it, expect } from 'vitest'
import { matchesDeviceFilter } from '../utils/deviceFilter.js'

const phone = { name: 'tapflow iPhone', id: 'AAAA-1' }
const tablet = { name: 'tapflow iPad', id: 'BBBB-2' }
const other = { name: 'cicd-smoke', id: 'CCCC-3' }

describe('matchesDeviceFilter', () => {
  it('passes everything without a filter', () => {
    expect(matchesDeviceFilter(undefined, other)).toBe(true)
  })

  it('matches one name or id, as before', () => {
    expect(matchesDeviceFilter('tapflow iPhone', phone)).toBe(true)
    expect(matchesDeviceFilter('AAAA-1', phone)).toBe(true)
    expect(matchesDeviceFilter('tapflow iPhone', tablet)).toBe(false)
  })

  it('matches any of several comma-separated entries, trimmed', () => {
    const filter = 'tapflow iPhone, tapflow iPad'
    expect([phone, tablet, other].filter((d) => matchesDeviceFilter(filter, d))).toEqual([phone, tablet])
  })

  it('ignores empty entries rather than matching a nameless device', () => {
    expect(matchesDeviceFilter('tapflow iPhone,,', { name: '', id: '' })).toBe(false)
  })
})
