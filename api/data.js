import { readBlob, writeBlob, isAdmin } from '../lib/util.js';
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') {
    const t = await readBlob('data.json');
    if (!t) return res.status(404).json({ error: 'belum ada data' });
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.status(200).send(t);
  }
  if (req.method === 'PUT') {
    if (!(await isAdmin(req))) return res.status(401).json({ error: 'Belum login admin' });
    const d = req.body;
    if (!d || typeof d !== 'object' || !Array.isArray(d.teams)) return res.status(400).json({ error: 'Data tidak valid' });
    await writeBlob('data.json', JSON.stringify(d));
    return res.status(200).json({ ok: true });
  }
  res.status(405).end();
}
