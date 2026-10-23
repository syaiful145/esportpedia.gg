import { sb, getUser, checkPw, hashPw, makeToken, cfgOk } from '../lib/peserta.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).end();
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi' });

  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Sesi habis, login lagi' });

  const { old = '', new: nw = '' } = req.body || {};
  if (!checkPw(old, user.pass_hash)) return res.status(403).json({ error: 'Password lama salah' });
  if (String(nw).length < 6) return res.status(400).json({ error: 'Password baru minimal 6 karakter' });

  const pass_hash = hashPw(String(nw));
  const r = await sb('peserta?id=eq.' + encodeURIComponent(user.id), {
    method: 'PATCH',
    body: JSON.stringify({ pass_hash }),
  });
  if (!r.ok) return res.status(500).json({ error: 'Gagal menyimpan password baru' });

  res.status(200).json({ token: makeToken({ ...user, pass_hash }) });
}
