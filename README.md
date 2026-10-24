# Artosku Admin

Website admin untuk mengelola Artosku (laptop dan HP): pengumuman, pengguna, biaya AI, kuota AI, versi rilis, fitur, dan parameter.

Halaman statis (HTML + JS), tanpa server sendiri. Bicara langsung ke Supabase project `klafrhlcxyyxdbrdenwk` memakai sesi admin yang sedang masuk.

## Keamanan
- Masuk dengan Google, lalu kode 6 digit (TOTP) dari aplikasi authenticator. Pertama kali: pindai QR yang tampil.
- Semua aksi lewat fungsi database `admin_*` (migrasi `0127_admin_console.sql` di repo acisku). Setiap fungsi memanggil `is_admin()`: email ada di tabel `admin_users` DAN sesi sudah lolos MFA (aal2). Halaman yang diubah di browser tetap ditolak server.
- Yang tersimpan di repo hanya URL project dan anon key (publik, sama seperti di app). Kunci service role tidak pernah ada di sini.
- Semua perubahan dicatat di tabel `admin_audit` (tampil di Rilis dan pengaturan).
- Push pengumuman lewat edge function `announce-push` yang memeriksa sesi admin yang sama.

## Admin
Akun admin ada di tabel `public.admin_users`. Menambah: `insert into public.admin_users(email) values ('...')`.
Kalau authenticator hilang: hapus faktornya di Supabase (Authentication, Users, pilih akun, MFA).

## Menjalankan di komputer
```
python -m http.server 8080
```
lalu buka `http://localhost:8080`. Alamat itu harus ada di Supabase, Authentication, URL Configuration, Redirect URLs.

## Berkas
- `index.html`, `css/app.css`, `js/app.js`, `js/config.js`
- `preview/index.html`: rancangan tampilan dengan data contoh
