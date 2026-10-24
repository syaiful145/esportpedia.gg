import { isAdmin } from '../lib/util.js';
import { sb, cfgOk } from '../lib/peserta.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!(await isAdmin(req))) return res.status(401).json({ error: 'Belum login admin' });
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi' });

  if (req.method === 'GET') {
    const r = await sb('tim_pengajuan?select=id,owner,payload,status,note,org_id,updated_at,peserta(username)&order=updated_at.desc&limit=100');
    if (!r.ok) return res.status(500).json({ error: 'Gagal membaca pengajuan (sudah membuat tabel tim_pengajuan di Supabase?)' });
    return res.status(200).json({ rows: r.data || [] });
  }

  if (req.method === 'PUT') {
    const { id = '', status = '', note = '', org_id = '', v = '' } = req.body || {};
    if (!id || !['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Permintaan tidak valid' });
    const g = await sb('tim_pengajuan?id=eq.' + encodeURIComponent(id) + '&select=payload,updated_at');
    const row = g.ok && g.data && g.data[0];
    if (!row) return res.status(404).json({ error: 'Pengajuan tidak ditemukan' });
    // Peserta mengubah pengajuan setelah admin membukanya -> minta muat ulang
    if (v && String(row.updated_at) !== String(v)) return res.status(409).json({ error: 'Pengajuan baru saja diubah peserta, muat ulang lalu cek lagi' });
    const body = status === 'approved'
      ? { status, note: '', org_id: String(org_id).slice(0, 40), live: row.payload }
      : { status, note: String(note).slice(0, 200) };
    const w = await sb('tim_pengajuan?id=eq.' + encodeURIComponent(id), { method: 'PATCH', body: JSON.stringify(body) });
    if (!w.ok) return res.status(500).json({ error: 'Gagal menyimpan keputusan' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    const id = String((req.body && req.body.id) || (req.query && req.query.id) || '');
    if (!id) return res.status(400).json({ error: 'Permintaan tidak valid' });
    const d = await sb('tim_pengajuan?id=eq.' + encodeURIComponent(id), { method: 'DELETE' });
    if (!d.ok) return res.status(500).json({ error: 'Gagal menghapus pengajuan' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}
