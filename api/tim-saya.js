import { sb, getUser, cfgOk } from '../lib/peserta.js';
import { cleanPayload } from '../lib/tim.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi' });
  const user = await getUser(req);
  if (!user) return res.status(401).json({ error: 'Sesi habis, login lagi' });

  const q = 'tim_pengajuan?owner=eq.' + encodeURIComponent(user.id) + '&select=id,payload,live,status,note,org_id,updated_at';
  const cur = await sb(q);
  if (!cur.ok) return res.status(500).json({ error: 'Gagal membaca pengajuan (sudah membuat tabel tim_pengajuan di Supabase?)' });
  const row = (cur.data && cur.data[0]) || null;

  if (req.method === 'GET') return res.status(200).json({ row });

  if (req.method === 'PUT') {
    const liveIds = ((row && row.live && row.live.divs) || []).map((d) => d.did);
    const r = cleanPayload(req.body && req.body.payload, liveIds);
    if (r.error) return res.status(400).json({ error: r.error });
    const stamp = new Date().toISOString();
    let w;
    if (row) {
      w = await sb('tim_pengajuan?id=eq.' + encodeURIComponent(row.id), {
        method: 'PATCH',
        body: JSON.stringify({ payload: r.value, status: 'pending', note: '', updated_at: stamp }),
      });
    } else {
      w = await sb('tim_pengajuan', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ owner: user.id, payload: r.value, status: 'pending', updated_at: stamp }),
      });
    }
    if (!w.ok) return res.status(500).json({ error: 'Gagal menyimpan pengajuan' });
    return res.status(200).json({ ok: true });
  }

  if (req.method === 'DELETE') {
    if (!row) return res.status(200).json({ ok: true });
    if (row.live) return res.status(409).json({ error: 'Tim ini sudah disetujui dan tampil di situs. Untuk menghapusnya hubungi admin.' });
    const d = await sb('tim_pengajuan?id=eq.' + encodeURIComponent(row.id), { method: 'DELETE' });
    if (!d.ok) return res.status(500).json({ error: 'Gagal menghapus pengajuan' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}
