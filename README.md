# KARTIKA-MIRAGE

**Kategori:** Penangkalan · Kartika Cyber Hackathon 2026
**Tim:** <Udang / Fatih Alfayruz>
**Video demo:** <https://youtu.be/lSGIWVmWZGQ> · **Slide penjelasan:** <https://canva.link/qakwju7zfhgdnbn>

**Masalah:** komunikasi dan pergerakan VVIP rawan disadap, sementara pemblokiran biasa justru
memberi tahu penyadap bahwa ia sudah terdeteksi.

**Solusi:** trafik yang mencurigakan tidak diblokir, tetapi dialihkan ke dokumen umpan yang
melapor balik (beacon), ditahan di tar-pit, dan dicatat di ledger forensik anti-manipulasi.

**Arsitektur:** tiga lapis pertahanan: Layer 1 autentikasi (token JWT berumur 60 detik) →
Layer 2 perilaku (Isolation Forest + aturan) → Layer 3 otorisasi (warrant dengan pemisahan wewenang).


Platform counter-surveillance: trafik yang mencurigakan tidak diblokir, tetapi dialihkan ke
dokumen umpan yang melapor balik (beacon) dan dicatat di ledger forensik anti-manipulasi.

## Menjalankan
```
pip install -r requirements.txt
bash run.sh          # Windows: run.bat
```
Buka http://127.0.0.1:8000. Saat pertama jalan, engine membuat rahasia acak di
`mirage-engine/data/.mirage_secrets.json` (JANGAN di-commit) dan melatih model ke
`mirage_behavior_model.joblib` (beberapa detik). Dashboard hanya otomatis mendapat kunci admin
bila dibuka dari mesin yang sama (localhost).

## Alur demo di dashboard
| Tombol | Skenario | Yang menangkap |
|---|---|---|
| Tahap 01 | Ajukan warrant -> disetujui pihak lain -> JWT 60 dtk -> akses sah | (lolos) |
| 02A | Token sah + warrant sah, dipakai bot burst | Layer 2 (perilaku) |
| 02B | Tanpa token | Layer 1 (autentikasi) |
| 02C | Token sah, perilaku normal, TANPA warrant | Layer 3 (otorisasi) -> INSIDER_ABUSE |
| Tahap 03 | Umpan dibuka di mesin penyadap -> beacon -> dossier + ledger | Counter-intel |

Di bawah log ada seksi **07 Otorisasi & Bukti Forensik**: registri warrant (siapa mengajukan, siapa
menyetujui) dan status ledger. Tombol **Simulasi Manipulasi Bukti** mengubah *salinan* ledger di
memori (database asli tidak disentuh) dan menunjukkan bahwa manipulasi terdeteksi, termasuk bila
penyerang menghitung ulang hash tanpa kunci ledger.

## Demo dua perangkat (penyadap sungguhan)
1. `cloudflared tunnel --url http://localhost:8000`
2. Jalankan engine dengan `TRUST_PROXY=1` dan `PUBLIC_BASE_URL=https://<url-tunnel>`.
3. Buka dashboard **hanya lewat http://127.0.0.1:8000** (jangan lewat URL tunnel).
4. Di perangkat lain buka `https://<url-tunnel>/gateway/vip-stream?format=html`: file umpan terunduh.
   Buka file itu: beacon aktif dan dossier di dashboard menampilkan perangkat tersebut.
   (Format default `pdf` dan `docx` memerlukan klik pada tautan; `html` menyala otomatis.)
5. Matikan tunnel setelah demo.

## Variabel lingkungan
`TRUST_PROXY=1` (percaya `cf-connecting-ip`), `PUBLIC_BASE_URL`, `MIRAGE_ADMIN_KEY`,
`MIRAGE_JWT_SECRET`, `MIRAGE_LEDGER_KEY`, `VIP_GATEWAY_TOKEN`, `ENRICH_ONLINE=1`
(lookup IP ke ip-api.com; MATI secara default karena mengirim IP penyadap ke pihak ketiga). `TARPIT_SPEED` (pengali jeda tar-pit, default 1.0).

## Batasan (jujur)
- Intersepsi nyata tidak ada: penyadap disimulasikan. Header `X-Simulated-Burst` hanya hook demo.
- Deteksi = Isolation Forest + aturan (hybrid). ROC-AUC dihitung pada data sintetis dari generator
  yang sama: bukan klaim akurasi dunia nyata.
- Lokasi penyadap hanya indikator (IP + timezone yang dilaporkan perangkat), bukan bukti.
- Pemisahan wewenang warrant membandingkan nama (kontrol tingkat demo, bukan identitas terverifikasi).
- Ledger berhash-HMAC mendeteksi manipulasi tanpa kunci; pemilik kunci tetap bisa menulis ulang.
- Beacon DOCX/PDF memerlukan klik; WAV hanya umpan tanpa beacon.
- Aset front-end disertakan lokal di `mirage-engine/static/vendor/`, jadi dashboard tidak bergantung pada CDN.

## Honeytoken (kredensial umpan)
Setiap dokumen umpan memuat blok "Akses portal koordinasi" dengan pengguna dan kata sandi unik per sesi
(turunan HMAC, tidak valid di sistem mana pun). Pemakaiannya di `POST /portal/login` atau sebagai
`Authorization: Bearer` / `X-VIP-Token` di gateway dicatat sebagai pemicu berkeyakinan TINGGI
(`honeytoken_portal` / `honeytoken_gateway`), lengkap dengan dossier dan blok ledger.
Beacon kini berlabel keyakinan: klik manual = tinggi, pixel/JS = sedang (bisa pemindai otomatis).
Demo: buka PDF umpan, ambil pengguna/kata sandi, lalu `curl -X POST :8000/portal/login -H 'content-type: application/json' -d '{"username":"...","password":"..."}'`.

## Red-team otomatis (uji diri, hanya localhost)
`cd red-team && python red_team_agent.py` menjalankan 10 skenario terhadap instance sendiri dan menulis
laporan JSON ke `red-team/reports/`: penyusup tanpa token, token bocor + bot, insider tanpa warrant,
persetujuan diri sendiri, warrant sah, pelanggaran kategori data, warrant dicabut, beacon via `/assets`,
honeytoken di portal, dan deteksi manipulasi ledger. Agen menolak target selain localhost.
Jalankan setelah engine dan gateway hidup; jalankan ulang setiap selesai mengubah kode.

## Tar-pit adaptif
Setelah kredensial umpan dipakai di `/portal/login`, penyerang menerima token sesi portal dan masuk ke
`/portal/files/...`: direktori dan berkas palsu yang dikirim baris demi baris dengan jeda.
- **Skrip/bot** (UA khas skrip atau jeda antar request < 2 dtk): jeda 4 dtk/baris, halaman tanpa akhir sampai batas durasi.
- **Manusia**: jeda singkat, halaman wajar dengan banyak tautan, supaya terus menjelajah dan meninggalkan jejak.
- Waktu terbuang tampil di dashboard (panel dossier); ringkasan tiap koneksi masuk ledger berantai.
- Batas pelindung (env): `TARPIT_MAX_CONNECTIONS=50`, `TARPIT_MAX_PER_IP=5`, `TARPIT_MAX_SECONDS=300`.
  Di atas batas, server menjawab 503 cepat. Murni di server sendiri; tidak ada kode di perangkat penyerang.

## Tahap 04 di dashboard (honeytoken + tar-pit)
Tombol "4. Penyerang Pakai Kredensial Umpan & Tertahan": penyerang simulasi memancing umpan HTML, membaca akun portal
dari dokumen, login, lalu menjelajah dengan pola skrip sehingga tertahan di tar-pit. Terminal penyerang tampil di
panel simulasi dengan penghitung waktu; tombol "PENYERANG MENYERAH" menghentikan. Gauge, panel Tar-Pit, dossier,
dan ledger ikut terisi. Semuanya berjalan terhadap server sendiri.

## Batas Etika
- Beacon umpan hanya melaporkan IP, zona waktu, dan resolusi layar perangkat yang membuka dokumen;
  tidak ada eksploitasi atau kerusakan pada perangkat tersebut.
- Seluruh pengujian dilakukan pada server dan perangkat milik sendiri. Tar-pit hanya berjalan di server sendiri.
- Red-team agent menolak target selain localhost.
- Lookup IP ke pihak ketiga mati secara default (`ENRICH_ONLINE`), sehingga tidak ada data pihak ketiga
  yang dikirim keluar tanpa pengaturan eksplisit.

## Atribusi & Pernyataan Orisinalitas
Karya ini dikembangkan oleh tim selama periode Kartika Cyber Hackathon 2026.
Tidak ada karya pre-existing yang dipakai sebagai dasar pengembangan.

Library pihak ketiga (open source, dipakai sesuai lisensinya):
- Backend: FastAPI, Uvicorn, Jinja2, HTTPX, PyJWT, NumPy, scikit-learn, joblib, fpdf2, python-docx
- Front-end (di `mirage-engine/static/vendor/`): Tailwind CSS, GSAP, TopoJSON, D3.js, dan font web (Oswald)
- Data pelatihan model deteksi dibuat secara sintetis oleh `train_ml_model.py`; tidak memakai data pribadi.
