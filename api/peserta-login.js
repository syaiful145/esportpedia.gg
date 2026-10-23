import { sb, checkPw, makeToken, cfgOk } from '../lib/peserta.js';

const fails = new Map();

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).end();
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi (cek Environment Variables di Vercel)' });

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0] || 'x';
  const now = Date.now();
  const f = (fails.get(ip) || []).filter((t) => now - t < 600000);
  if (f.length >= 8) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi 10 menit lagi' });

  const { username = '', password = '' } = req.body || {};
  const u = String(username).trim().toLowerCase();

  let row = null;
  if (u) {
    const r = await sb('peserta?username=eq.' + encodeURIComponent(u) + '&select=id,username,pass_hash');
    row = r.ok && r.data && r.data[0];
  }

  if (!row || !checkPw(password, row.pass_hash)) {
    f.push(now);
    fails.set(ip, f);
    await new Promise((r) => setTimeout(r, 1000));
    return res.status(401).json({ error: 'Username atau password salah' });
  }

  fails.delete(ip);
  res.status(200).json({ token: makeToken(row), username: row.username });
}
