# Artosku Admin

Website admin untuk mengelola Artosku (laptop dan HP): pengumuman, pengguna, biaya AI, kuota AI, versi rilis, fitur uji, dan parameter.

Status: rancangan tampilan saja (`preview/index.html`, data contoh). Belum tersambung ke server.

## Rencana singkat
- Halaman statis (tanpa server sendiri), bicara langsung ke Supabase project `klafrhlcxyyxdbrdenwk`.
- Masuk dengan Google; hanya akun dengan tanda admin di server yang diterima. Pemeriksaan ada di server (RLS dan fungsi), bukan hanya di halaman.
- Kunci rahasia (service role) tidak pernah ada di repo atau di halaman.
- Aksi yang mengubah banyak akun (reset kuota semua user) minta konfirmasi ketik.

## Query tersimpan yang menjadi panel
Count Registered User, Check New User, Lihat Cost, Call Per User, Cost Per User, API Call, Reset Quota AI All User, Toggle Streak Test, Update Min Version, Select URL.
