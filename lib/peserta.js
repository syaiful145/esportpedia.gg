import crypto from 'node:crypto';

const BASE = () => (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = () => process.env.SUPABASE_SECRET_KEY || '';

export const cfgOk = () => !!BASE() && !!KEY();

// Panggil Supabase REST dengan secret key (hanya di server, tidak pernah ke browser)
export async function sb(path, opt = {}) {
  const r = await fetch(BASE() + '/rest/v1/' + path, {
    ...opt,
    headers: { apikey: KEY(), 'Content-Type': 'application/json', ...(opt.headers || {}) },
  });
  const t = await r.text();
  let data = null;
  try { data = t ? JSON.parse(t) : null; } catch { data = null; }
  return { ok: r.ok, status: r.status, data };
}

export function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pw), salt, 64).toString('hex');
}

export function checkPw(pw, stored) {
  const [salt, h] = String(stored || '').split(':');
  if (!salt || !h) return false;
  const a = crypto.scryptSync(String(pw), salt, 64);
  const b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const b64 = (s) => Buffer.from(s).toString('base64url');
const mac = (s) => crypto.createHmac('sha256', 'peserta:' + KEY()).update(s).digest('base64url');

// Token berlaku 12 jam dan otomatis hangus kalau password diganti/direset
export function makeToken(user) {
  const p = b64(JSON.stringify({
    id: user.id,
    u: user.username,
    ph: String(user.pass_hash).slice(-12),
    exp: Date.now() + 12 * 3600 * 1000,
  }));
  return p + '.' + mac(p);
}

export async function getUser(req) {
  if (!cfgOk()) return null;
  const t = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const [p, m] = t.split('.');
  if (!p || !m) return null;
  const e = mac(p);
  if (e.length !== m.length || !crypto.timingSafeEqual(Buffer.from(e), Buffer.from(m))) return null;
  let d;
  try { d = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return null; }
  if (!d || !d.id || d.exp < Date.now()) return null;
  const r = await sb('peserta?id=eq.' + encodeURIComponent(d.id) + '&select=id,username,pass_hash');
  const u = r.ok && r.data && r.data[0];
  if (!u || String(u.pass_hash).slice(-12) !== d.ph) return null;
  return u;
}

export const okUsername = (u) => /^[a-z0-9._-]{3,32}$/.test(u);
