import { readBlob, writeBlob, isAdmin } from '../lib/util.js';
import { getUser } from '../lib/peserta.js';
import crypto from 'crypto';
export default async function handler(req, res) {
  if (req.method !== 'GET') res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET') {
    // Data hanya untuk yang sudah login (admin atau peserta)
    if (!(await isAdmin(req)) && !(await getUser(req))) return res.status(401).json({ error: 'Harus login' });
    const t = await readBlob('data.json');
    if (!t) return res.status(404).json({ error: 'belum ada data' });
    // ETag: kalau data belum berubah, balas 304 (hemat kuota, cepat untuk cek realtime)
    const etag = '"' + crypto.createHash('sha1').update(t).digest('hex') + '"';
    res.setHeader('ETag', etag);
    res.setHeader('Cache-Control', 'no-cache');
    if (req.headers['if-none-match'] === etag) return res.status(304).end();
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
