import { adminOk, adminVer, sign, same } from '../lib/util.js';
const fails = new Map();
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0] || 'x', now = Date.now();
  const f = (fails.get(ip) || []).filter(t => now - t < 600000);
  if (f.length >= 8) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi 10 menit lagi' });
  const { role, password = '' } = req.body || {};
  let ok = false;
  if (role === 'admin') ok = await adminOk(password);
  else if (role === 'viewer') ok = !!process.env.VIEWER_PASSWORD && same(password, process.env.VIEWER_PASSWORD);
  if (!ok) { f.push(now); fails.set(ip, f); await new Promise(r => setTimeout(r, 1000)); return res.status(401).json({ error: 'Password salah' }); }
  fails.delete(ip);
  res.status(200).json({ token: role === 'admin' ? sign('admin', await adminVer()) : '' });
}
