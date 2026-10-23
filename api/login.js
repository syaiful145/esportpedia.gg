import { adminOk, adminVer, sign, same } from '../lib/util.js';
import { sb, checkPw, cfgOk } from '../lib/peserta.js';
const fails = new Map();
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0] || 'x', now = Date.now();
  const f = (fails.get(ip) || []).filter(t => now - t < 600000);
  if (f.length >= 8) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi 10 menit lagi' });
  const { role, password = '', username = '' } = req.body || {};
  let ok = false, token = '', name = '';
  if (role === 'admin') {
    const u = String(username).trim().toLowerCase();
    if (u) {
      // Login admin dari database (username + password)
      if (cfgOk()) {
        const r = await sb('admin?username=eq.' + encodeURIComponent(u) + '&select=id,username,pass_hash');
        const row = r.ok && r.data && r.data[0];
        if (row && checkPw(password, row.pass_hash)) {
          ok = true; name = row.username;
          token = sign('admin', 'db:' + row.id + ':' + String(row.pass_hash).slice(-12));
        }
      }
    } else if (await adminOk(password)) {
      // Username kosong: sandi admin utama (cadangan)
      ok = true; token = sign('admin', await adminVer());
    }
  } else if (role === 'viewer') ok = !!process.env.VIEWER_PASSWORD && same(password, process.env.VIEWER_PASSWORD);
  if (!ok) { f.push(now); fails.set(ip, f); await new Promise(r => setTimeout(r, 1000)); return res.status(401).json({ error: 'Username atau password salah' }); }
  fails.delete(ip);
  res.status(200).json({ token: role === 'admin' ? token : '', username: name });
}
