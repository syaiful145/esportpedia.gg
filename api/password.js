import { isAdmin, adminOk, hashPw, writeBlob, authPath, adminVer, sign } from '../lib/util.js';
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  if (!(await isAdmin(req))) return res.status(401).json({ error: 'Belum login admin' });
  const { old = '', new: nw = '' } = req.body || {};
  if (!(await adminOk(old))) return res.status(403).json({ error: 'Sandi lama salah' });
  if (String(nw).length < 8) return res.status(400).json({ error: 'Sandi baru minimal 8 karakter' });
  await writeBlob(authPath(), JSON.stringify({ hash: hashPw(String(nw)) }));
  res.status(200).json({ token: sign('admin', await adminVer()) });
}
