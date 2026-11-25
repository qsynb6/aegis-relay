import crypto from 'node:crypto';
import net from 'node:net';

export const b64u = b => Buffer.from(b).toString('base64url');
export const randomToken = (bytes = 32) => b64u(crypto.randomBytes(bytes));
export const timingEqual = (a, b) => {
  const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

export function deriveKey(secret) {
  if (!secret || Buffer.byteLength(secret) < 32) throw new Error('APP_MASTER_KEY must be at least 32 bytes');
  return crypto.scryptSync(secret, 'aegis-relay:v1', 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

export function hashPassword(password, salt = crypto.randomBytes(16)) {
  const raw = String(password);
  if (raw.length < 14) throw new Error('password must contain at least 14 characters');
  if (raw.length > 1024) throw new Error('password must not exceed 1024 characters');
  const digest = crypto.scryptSync(raw, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$32768$${b64u(salt)}$${b64u(digest)}`;
}

export function verifyPassword(password, encoded) {
  try {
    const raw = String(password);
    if (raw.length > 1024) return false;
    const [kind, n, salt, expected] = encoded.split('$');
    if (kind !== 'scrypt' || n !== '32768') return false;
    const actual = crypto.scryptSync(raw, Buffer.from(salt, 'base64url'), 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    return timingEqual(actual, Buffer.from(expected, 'base64url'));
  } catch { return false; }
}

export async function verifyPasswordAsync(password, encoded) {
  try {
    const raw = String(password);
    if (raw.length > 1024) return false;
    const [kind, n, salt, expected] = String(encoded || '').split('$');
    if (kind !== 'scrypt' || n !== '32768' || !salt || !expected) return false;
    const actual = await new Promise((resolve, reject) => {
      crypto.scrypt(raw, Buffer.from(salt, 'base64url'), 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derived) => {
        if (err) reject(err);
        else resolve(derived);
      });
    });
    return timingEqual(actual, Buffer.from(expected, 'base64url'));
  } catch { return false; }
}

export const tokenDigest = (token, key) => b64u(crypto.createHmac('sha256', key).update(token).digest());

export function newTotpSecret() {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', bytes=crypto.randomBytes(20); let bits='', out='';
  for(const b of bytes) bits+=b.toString(2).padStart(8,'0'); for(let i=0;i<bits.length;i+=5) out+=alphabet[parseInt(bits.slice(i,i+5).padEnd(5,'0'),2)]; return out;
}

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const ch of value.replaceAll(' ', '').toUpperCase()) {
    const i = alphabet.indexOf(ch); if (i < 0) throw new Error('invalid base32');
    bits += i.toString(2).padStart(5, '0');
  }
  const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

export function totp(secret, at = Date.now(), step = 30) {
  const counter = Math.floor(at / 1000 / step); const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest(); const off = h[h.length - 1] & 15;
  return String((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

export function verifyTotpStep(secret, code, now = Date.now(), lastUsedStep = null) {
  if (!/^\d{6}$/.test(String(code))) return null;
  let matchedStep = null;
  for (const w of [-1, 0, 1]) {
    const t = now + w * 30000;
    if (t >= 0 && timingEqual(totp(secret, t), code)) {
      matchedStep = Math.floor(t / 1000 / 30);
      break;
    }
  }
  if (matchedStep === null) return null;
  if (lastUsedStep !== null && lastUsedStep !== undefined && matchedStep <= Number(lastUsedStep)) return null;
  return matchedStep;
}

export function verifyTotp(secret, code, now = Date.now()) {
  return verifyTotpStep(secret, code, now) !== null;
}

export function isPrivateIP(ip) {
  ip = String(ip || '').trim().toLowerCase().replace(/^::ffff:/, '');
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    return a === 0 || a === 10 || (a === 100 && b >= 64 && b <= 127) || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0 && c === 0) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    return ip === '::1' || ip === '::' || /^0(:0){6}:0?1$/.test(ip) || /^0(:0){7}$/.test(ip) || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb') || ip.startsWith('ff') || ip.startsWith('64:ff9b:');
  }
  return true;
}

export function cleanAlias(v) {
  v = String(v || '').toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(v)) throw new Error('alias must be 1-32 lowercase letters, digits, _ or -');
  return v;
}

export class RateLimiter {
  constructor(limit = 5, windowMs = 60000, maxKeys = 4096) { this.limit = limit; this.windowMs = windowMs; this.maxKeys = maxKeys; this.map = new Map(); }
  take(key, now = Date.now()) {
    // Keys are attacker-controlled (one per client IP), so the table must stay bounded: sweep
    // expired windows first, then drop the oldest entries rather than growing without limit.
    if (this.map.size >= this.maxKeys) {
      for (const [k, v] of this.map) if (now - v.start >= this.windowMs) this.map.delete(k);
      for (const [k] of this.map) { if (this.map.size < this.maxKeys) break; this.map.delete(k); }
    }
    const cur = this.map.get(key); if (!cur || now - cur.start >= this.windowMs) { this.map.set(key, { start: now, count: 1 }); return true; }
    cur.count++; return cur.count <= this.limit;
  }
}

export class LoginGuard {
  constructor(threshold = 5, baseDelayMs = 15_000, maxDelayMs = 15 * 60_000) {
    this.threshold = threshold;
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.failures = 0;
    this.lockedUntil = 0;
  }
  check(now = Date.now()) {
    return {
      allowed: now >= this.lockedUntil,
      retryAfter: Math.max(0, Math.ceil((this.lockedUntil - now) / 1000))
    };
  }
  recordFailure(now = Date.now()) {
    this.failures++;
    if (this.failures >= this.threshold) {
      this.lockedUntil = now + Math.min(this.maxDelayMs, this.baseDelayMs * (2 ** Math.min(this.failures - this.threshold, 8)));
    }
  }
  recordSuccess() {
    this.failures = 0;
    this.lockedUntil = 0;
  }
}

// The panel refuses X-Forwarded-For from clients, but our own Nginx on the same host (or Docker
// bridge gateway when ports are bound only to 127.0.0.1) sets X-Real-IP. Trust that single hop
// only when the TCP peer is loopback, an explicitly trusted proxy, or a local private bridge peer
// when container ports are host-loopback-bound.
export function requestIp(req, env = process.env) {
  const remote = String(req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
  const trustedList = String(env.TRUSTED_PROXIES || '').split(',').map(s => s.trim()).filter(Boolean);
  const dockerLocalBound = env.ADMIN_PUBLISH_IP === '127.0.0.1' || env.PROXY_PUBLISH_IP === '127.0.0.1';
  const isPrivatePeer = net.isIP(remote) !== 0 && isPrivateIP(remote);
  const trusted = remote === '127.0.0.1' || remote === '::1'
    || trustedList.includes(remote)
    || (trustedList.includes('private') && isPrivatePeer)
    || (dockerLocalBound && isPrivatePeer);
  if (trusted) {
    const real = String(req.headers?.['x-real-ip'] || '').split(',')[0].trim().replace(/^::ffff:/, '');
    if (net.isIP(real)) return real;
  }
  return remote;
}
