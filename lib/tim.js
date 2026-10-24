// Validasi pengajuan tim dari peserta (dijalankan di server, jangan percaya data dari browser)
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

export function cleanPayload(p, liveIds = []) {
  if (!p || typeof p !== 'object') return { error: 'Data tidak valid' };
  const o = p.org || {};
  const n = str(o.n, 40);
  if (n.length < 2) return { error: 'Nama tim minimal 2 karakter' };
  const t = str(o.t || n, 40).replace(/[^A-Za-z0-9]/g, '').slice(0, 4).toUpperCase();
  if (!t) return { error: 'Tag tim tidak valid (huruf/angka, maks. 4)' };
  const c = str(o.c, 2).toUpperCase();
  if (c && !/^[A-Z]{2}$/.test(c)) return { error: 'Negara harus 2 huruf, misal ID' };
  const desc = str(o.desc, 300);
  let logo = '';
  if (o.logo) {
    logo = String(o.logo);
    if (logo.length > 200000 || !/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(logo)) return { error: 'Logo tidak valid atau terlalu besar' };
  }
  if (!Array.isArray(p.divs) || p.divs.length < 1) return { error: 'Tambahkan minimal 1 divisi' };
  if (p.divs.length > 6) return { error: 'Maksimal 6 divisi' };
  const seen = new Set();
  const divs = [];
  for (const d of p.divs) {
    const did = str(d && d.did, 20);
    if (!/^[a-z0-9]{4,20}$/.test(did) || seen.has(did)) return { error: 'Divisi tidak valid' };
    seen.add(did);
    const dn = str(d.n, 50);
    if (dn.length < 2) return { error: 'Nama divisi minimal 2 karakter' };
    const g = str(d.g, 40);
    if (g && !/^[A-Za-z0-9_-]+$/.test(g)) return { error: 'Game tidak valid' };
    if (!Array.isArray(d.r) || d.r.length > 12) return { error: 'Maksimal 12 pemain per divisi' };
    const r = d.r.map((x) => [str(Array.isArray(x) ? x[0] : '', 24) || 'TBD', str(Array.isArray(x) ? x[1] : '', 24)]);
    divs.push({ did, n: dn, g, r });
  }
  for (const id of liveIds) if (!seen.has(id)) return { error: 'Divisi yang sudah disetujui tidak bisa dihapus oleh peserta, minta admin' };
  return { value: { org: { n, t, c, desc, logo }, divs } };
}
