import { isAdmin } from '../lib/util.js';
import { sb, hashPw, cfgOk, okUsername } from '../lib/peserta.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!(await isAdmin(req))) return res.status(401).json({ error: 'Belum login admin' });
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi (cek Environment Variables di Vercel)' });

  // Daftar peserta (tanpa hash password)
  if (req.method === 'GET') {
    const r = await sb('peserta?select=id,username,created_at&order=created_at.desc');
    if (!r.ok) return res.status(500).json({ error: 'Gagal membaca tabel peserta (sudah membuat tabel di Supabase?)' });
    return res.status(200).json({ users: r.data || [] });
  }

  // Tambah peserta
  if (req.method === 'POST') {
    const { username = '', password = '' } = req.body || {};
    const u = String(username).trim().toLowerCase();
    if (!okUsername(u)) return res.status(400).json({ error: 'Username 3-32 karakter: huruf kecil, angka, titik, strip' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    const r = await sb('peserta', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ username: u, pass_hash: hashPw(String(password)) }),
    });
    if (r.status === 409) return res.status(409).json({ error: 'Username sudah ada' });
    if (!r.ok) return res.status(500).json({ error: 'Gagal menambah peserta' });
    return res.status(200).json({ ok: true });
  }

  // Reset password peserta
  if (req.method === 'PUT') {
    const { id = '', password = '' } = req.body || {};
    if (!id) return res.status(400).json({ error: 'ID tidak ada' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    const r = await sb('peserta?id=eq.' + encodeURIComponent(id), {
      method: 'PATCH',
      body: JSON.stringify({ pass_hash: hashPw(String(password)) }),
    });
    if (!r.ok) return res.status(500).json({ error: 'Gagal reset password' });
    return res.status(200).json({ ok: true });
  }

  // Hapus peserta
  if (req.method === 'DELETE') {
    const id = String((req.query && req.query.id) || '');
    if (!id) return res.status(400).json({ error: 'ID tidak ada' });
    const r = await sb('peserta?id=eq.' + encodeURIComponent(id), { method: 'DELETE' });
    if (!r.ok) return res.status(500).json({ error: 'Gagal menghapus' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}
