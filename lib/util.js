import crypto from 'node:crypto';
import { put, head, get } from '@vercel/blob';
import { sb } from './peserta.js';
const SECRET = process.env.SESSION_SECRET || '';
// Token store private (prefix PRIV saat connect di Vercel)
const PRIV_TOKEN = process.env.PRIV_READ_WRITE_TOKEN;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
export const authPath = () => 'auth-' + sha('p' + SECRET).slice(0, 32) + '.json';
// Baca file private. Kalau belum ada di store private, baca versi lama (public) sekali.
export async function readBlob(path) {
  let r = null;
  try { r = await get(path, { access: 'private', token: PRIV_TOKEN }); } catch (e) { r = null; }
  if (r && r.statusCode === 200 && r.stream) return await new Response(r.stream).text();
  if (r) return null;
  try { const m = await head(path); const x = await fetch(m.url + '?t=' + Date.now(), { cache: 'no-store' }); return x.ok ? await x.text() : null; }
  catch (e) { return null; }
}
export const writeBlob = (path, body) => put(path, body, { access: 'private', token: PRIV_TOKEN, addRandomSuffix: false, allowOverwrite: true, contentType: 'application/json' });
export const same = (a, b) => crypto.timingSafeEqual(Buffer.from(sha(String(a))), Buffer.from(sha(String(b))));
export function hashPw(pw) { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); }
export function checkHash(pw, st) { const [s, k] = st.split(':'); return same(crypto.scryptSync(pw, s, 32).toString('hex'), k); }
export async function adminVer() { const a = await readBlob(authPath()); return a ? JSON.parse(a).hash.slice(0, 12) : 'env'; }
export async function adminOk(pw) {
  const a = await readBlob(authPath());
  if (a) return checkHash(pw, JSON.parse(a).hash);
  return !!process.env.ADMIN_PASSWORD && same(pw, process.env.ADMIN_PASSWORD);
}
export function sign(role, v) {
  const p = Buffer.from(JSON.stringify({ r: role, v, e: Date.now() + 8 * 3600e3 })).toString('base64url');
  return p + '.' + crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
}

// Baca token admin dari header; null kalau tanda tangan salah atau sudah kedaluwarsa
function tokenOf(req) {
  const [p, sg] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!p || !sg) return null;
  const ok = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  if (!same(sg, ok)) return null;
