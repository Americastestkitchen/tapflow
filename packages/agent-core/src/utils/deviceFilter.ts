/**
 * Whether a device passes an agent's `--device` filter: its name or id equals one of the
 * comma-separated entries. One filter can then name several devices (a phone and a tablet, or
 * devices of both platforms for `tapflow start`), while a filter of one name behaves exactly as
 * before. Entries are trimmed so `"iPhone, iPad"` reads the way it was typed.
 */
export function matchesDeviceFilter(filter: string | undefined, device: { name: string; id: string }): boolean {
  if (!filter) return true
  return filter.split(',').some((entry) => {
    const want = entry.trim()
    return want !== '' && (device.name === want || device.id === want)
  })
}
