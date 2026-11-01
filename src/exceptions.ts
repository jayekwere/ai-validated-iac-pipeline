// Scanner exceptions are reviewed, time-boxed decisions, not permanent allowances.
// Every entry must name one finding on one resource, cite primary documentation and
// carry an expiry no more than MAX_EXCEPTION_DAYS ahead. An expired, malformed or
// duplicate entry fails the Trivy security decision instead of silently applying.

export type ScannerException = { id: string; resource: string; reason: string; source: string; expires: string };

export const MAX_EXCEPTION_DAYS = 365;
const FIELDS = ['id', 'resource', 'reason', 'source', 'expires'];
const DAY_MS = 86_400_000;

function utcDay(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return NaN;
  const time = Date.parse(value + 'T00:00:00Z');
  return Number.isNaN(time) || new Date(time).toISOString().slice(0, 10) !== value ? NaN : time;
}

export function activeScannerExceptions(doc: unknown, now: Date = new Date()): ScannerException[] {
  if (typeof doc !== 'object' || doc === null || !Array.isArray((doc as any).exceptions)) throw Error('EXCEPTIONS_FORMAT: expected an exceptions array');
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const seen = new Set<string>();
  return (doc as any).exceptions.map((entry: any, index: number): ScannerException => {
    const where = `exception ${index}`;
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw Error(`EXCEPTION_FORMAT: ${where} is not an object`);
    const keys = Object.keys(entry).sort();
    if (keys.join() !== [...FIELDS].sort().join()) throw Error(`EXCEPTION_FORMAT: ${where} must have exactly ${FIELDS.join(', ')}`);
    for (const field of FIELDS) if (typeof entry[field] !== 'string' || entry[field].trim() === '') throw Error(`EXCEPTION_FORMAT: ${where} ${field} must be a non-empty string`);
    if (!/^[A-Z]+(-[A-Z]+)?-\d{4}$/.test(entry.id)) throw Error(`EXCEPTION_FORMAT: ${where} id ${entry.id} is not a scanner check ID`);
    if (!entry.source.startsWith('https://')) throw Error(`EXCEPTION_FORMAT: ${where} source must be an https documentation URL`);
    const key = entry.id + '\u0000' + entry.resource;
    if (seen.has(key)) throw Error(`EXCEPTION_DUPLICATE: ${entry.id} on ${entry.resource}`);
    seen.add(key);
    const expires = utcDay(entry.expires);
    if (Number.isNaN(expires)) throw Error(`EXCEPTION_FORMAT: ${where} expires must be a valid YYYY-MM-DD date`);
    if (expires < today) throw Error(`EXCEPTION_EXPIRED: ${entry.id} on ${entry.resource} expired ${entry.expires}; re-review it or remove it`);
    if (expires > today + MAX_EXCEPTION_DAYS * DAY_MS) throw Error(`EXCEPTION_TOO_LONG: ${entry.id} on ${entry.resource} expires more than ${MAX_EXCEPTION_DAYS} days ahead`);
    return { id: entry.id, resource: entry.resource, reason: entry.reason, source: entry.source, expires: entry.expires };
  });
}
