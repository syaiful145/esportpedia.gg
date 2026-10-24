import { adminCtx } from '../lib/util.js';
import { sb, hashPw, cfgOk, okUsername } from '../lib/peserta.js';

// Aturan:
// - Admin utama = login dengan username kosong (sandi env/blob). Tidak ada di tabel admin.
// - Admin kedua = baris di tabel admin.
// - Hanya admin utama yang bisa menambah dan menghapus admin.
// - Admin kedua hanya bisa mengganti sandinya sendiri, tidak bisa mengubah admin lain.
// - Admin utama tidak bisa dihapus (tidak ada di tabel), dan tidak bisa diubah admin kedua.

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const me = await adminCtx(req);
  if (!me) return res.status(401).json({ error: 'Belum login admin' });
  if (!cfgOk()) return res.status(500).json({ error: 'Server belum dikonfigurasi (cek Environment Variables di Vercel)' });

  // Tentukan apakah pemanggil admin utama: id-nya tidak ada di tabel admin.
  // Kalau cek database gagal, tolak (fail closed) supaya tidak salah dianggap admin utama.
  let isMain = true;
  if (me.id) {
    const q = await sb('admin?id=eq.' + encodeURIComponent(me.id) + '&select=id');
    if (!q.ok) return res.status(500).json({ error: 'Gagal memeriksa akun admin' });
    isMain = !(q.data && q.data.length);
  }

  // Daftar admin (tanpa hash password)
  if (req.method === 'GET') {
    const r = await sb('admin?select=id,username,created_at&order=created_at.asc');
    if (!r.ok) return res.status(500).json({ error: 'Gagal membaca tabel admin (sudah membuat tabel admin di Supabase?)' });
    return res.status(200).json({ users: r.data || [], me: me.id, isMain });
  }

  // Tambah admin: hanya admin utama
  if (req.method === 'POST') {
    if (!isMain) return res.status(403).json({ error: 'Hanya admin utama yang bisa menambah admin' });
    const { username = '', password = '' } = req.body || {};
    const u = String(username).trim().toLowerCase();
    if (!okUsername(u)) return res.status(400).json({ error: 'Username 3-32 karakter: huruf kecil, angka, titik, strip' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    const r = await sb('admin', {
      method: 'POST',
      headers: { Prefer: 'return=minimal' },
      body: JSON.stringify({ username: u, pass_hash: hashPw(String(password)) }),
    });
    if (r.status === 409) return res.status(409).json({ error: 'Username sudah ada' });
    if (!r.ok) return res.status(500).json({ error: 'Gagal menambah admin' });
    return res.status(200).json({ ok: true });
  }

  // Reset password: admin utama bisa untuk siapa saja di tabel, admin kedua hanya untuk dirinya sendiri
  if (req.method === 'PUT') {
    const { id = '', password = '' } = req.body || {};
    if (!id) return res.status(400).json({ error: 'ID tidak ada' });
    const self = id === me.id;
    if (!self && !isMain) return res.status(403).json({ error: 'Admin kedua hanya bisa mengganti sandinya sendiri' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password minimal 6 karakter' });
    const r = await sb('admin?id=eq.' + encodeURIComponent(id), {
      method: 'PATCH',
      body: JSON.stringify({ pass_hash: hashPw(String(password)) }),
    });
    if (!r.ok) return res.status(500).json({ error: 'Gagal reset password' });
    return res.status(200).json({ ok: true, self });
  }

  // Hapus admin: hanya admin utama, dan akun sendiri tidak boleh dihapus
  if (req.method === 'DELETE') {
    if (!isMain) return res.status(403).json({ error: 'Hanya admin utama yang bisa menghapus admin' });
    const id = String((req.query && req.query.id) || '');
    if (!id) return res.status(400).json({ error: 'ID tidak ada' });
    if (id === me.id) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
    const r = await sb('admin?id=eq.' + encodeURIComponent(id), { method: 'DELETE' });
    if (!r.ok) return res.status(500).json({ error: 'Gagal menghapus' });
    return res.status(200).json({ ok: true });
  }

  res.status(405).end();
}
