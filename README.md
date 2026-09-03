# ecome-engine

# ⚡ StoreEngine SaaS: Multi-Tenant Dynamic E-Commerce & Dual Payment Engine (Midtrans & PayPal)

**StoreEngine SaaS** adalah platform e-commerce multi-tenant modern yang beroperasi sepenuhnya di arsitektur *serverless edge* **Cloudflare Workers**. 

Platform ini memungkinkan setiap pemilik toko (*merchant*) untuk menentukan **Skema Atribut Dinamis** (tanpa migrasi database SQL), mengelola kredensial **Midtrans Payment Gateway** secara mandiri (dana penjualan langsung masuk ke rekening masing-masing merchant), serta menyediakan fitur monetisasi platform menggunakan **PayPal Subscription Engine**.

---

## 🌟 Fitur Utama

- 🏢 **Multi-Tenant Architecture**: Sistem autentikasi mandiri (Registrasi/Login) berbasis token JWT & Web Crypto PBKDF2 native. Setiap merchant memiliki toko, produk, pesanan, dan konfigurasinya sendiri.
- 🧩 **Dynamic Product Schema (Zero Migration)**: Merchant bebas membuat atribut kustom (ukuran pakaian, varian warna, kapasitas RAM, opsi rasa, level pedas, garansi) yang disimpan secara fleksibel dalam format JSON di database relasional **Cloudflare D1**.
- 💳 **Dinamis Midtrans Gateway per Tenant**:
  - Merchant memasukkan `Client Key` dan `Server Key` Midtrans mereka sendiri di dashboard toko.
  - Dana transaksi penjualan langsung masuk ke akun Midtrans masing-masing merchant.
  - Endpoint Webhook dinamis (`/api/midtrans-webhook/:storeId`) dengan verifikasi **Signature SHA-512** otomatis per toko.
- 💵 **SaaS Monetization via PayPal**: Integrasi paket langganan merchant (*Free*, *Pro*, *Enterprise*) yang terhubung langsung ke [PayPal Workers Engine](https://github.com/daffadevhosting/paypal-workers) (`https://paypal-pay.mvstream.workers.dev`).
- ⚡ **Penuh di Ekosistem Cloudflare Edge**:
  - **Cloudflare D1**: Database relasional SQL untuk multi-tenant, katalog, pesanan, dan histori langganan.
  - **Cloudflare KV**: *Edge caching* untuk skema atribut aktif dan metadata toko (*sub-millisecond latency*).
  - **Cloudflare Durable Objects**: Manajemen sesi keranjang belanja *real-time* & *inventory locking*.
  - **Cloudflare R2**: Penyimpanan objek media dan foto produk.

---

## 🏗️ Arsitektur Alur Sistem

```text
                               ┌─────────────────────────────────────────┐
                               │       Pelanggan / Pembeli Toko          │
                               └────────────────────┬────────────────────┘
                                                    │
                                                    ▼
┌───────────────────────────┐          ┌─────────────────────────┐
│     Merchant / Admin      │          │   Cloudflare Workers    │
│    (Dashboard & Toko)     ├─────────►│     (Hono Framework)    │
└─────────────┬─────────────┘          └────┬───────────────┬────┘
              │                             │               │
              │ (Langganan SaaS)            │ (Katalog/Data)│ (Transaksi Produk)
              ▼                             ▼               ▼
┌───────────────────────────┐    ┌─────────────────┐ ┌──────────────────────┐
│  PayPal Workers Gateway   │    │  Cloudflare D1  │ │  Midtrans Snap API   │
│  (Monetisasi Pemilik App) │    │  KV Cache & R2  │ │  (Akun Mandiri Toko) │
└───────────────────────────┘    └─────────────────┘ └──────────────────────┘
```

---

## 📁 Struktur File Repositori

```text
├── src/
│   └── ecome.ts            # Kode utama Cloudflare Worker (API, Auth, Logic, & Frontend SPA)
├── schema.sql               # Skema Database Cloudflare D1 SQL Multi-Tenant
├── wrangler.toml            # Konfigurasi Environment & Binding Cloudflare
├── package.json             # Dependensi & Skrip Node.js
└── README.md                # Dokumentasi Repositori
```

---

## 🚀 Panduan Instalasi & Deployment

### 1. Prasyarat
- [Node.js](https://nodejs.org/) (versi 18 atau lebih baru)
- Akun [Cloudflare](https://dash.cloudflare.com/)
- Akun [Midtrans](https://dashboard.sandbox.midtrans.com/) (untuk pengujian gateway)
- Cloudflare Wrangler CLI terpasang secara global (`npm install -g wrangler`)

### 2. Kloning Repositori & Pasang Dependensi
```bash
git clone [https://github.com/daffadevhosting/ecome-engine.git](https://github.com/daffadevhosting/ecome-engine.git)
cd ecome-engine
npm install
```

### 3. Login ke Cloudflare & Siapkan Resource
```bash
# Login akun Cloudflare Anda
wrangler login

# 1. Buat Database Cloudflare D1
wrangler d1 create store-db
# Salin `database_id` yang muncul di terminal ke wrangler.toml

# 2. Buat KV Namespace untuk Caching
wrangler kv:namespace create STORE_KV
# Salin `id` yang muncul di terminal ke wrangler.toml

# 3. Buat R2 Bucket untuk Foto Produk
wrangler r2 bucket create store-product-images
```

### 4. Konfigurasi `wrangler.toml`
Pastikan file `wrangler.toml` Anda sudah memetakan ID resource dengan benar:

```toml
name = "cloudflare-store-engine"
main = "src/worker.ts"
compatibility_date = "2024-01-01"

# Binding Database D1
[[d1_databases]]
binding = "DB"
database_name = "store-db"
database_id = "MASUKKAN_DATABASE_ID_D1_ANDA"

# Binding KV Cache
[[kv_namespaces]]
binding = "STORE_KV"
id = "MASUKKAN_KV_NAMESPACE_ID_ANDA"

# Binding Durable Objects (Keranjang Belanja)
[durable_objects]
bindings = [
  { name = "CART_DO", class_name = "CartSession" }
]

[[migrations]]
tag = "v1"
new_classes = ["CartSession"]

# Binding R2 Storage
[[r2_buckets]]
binding = "PRODUCT_BUCKET"
bucket_name = "store-product-images"

[vars]
PAYPAL_WORKER_URL = "[https://paypal-pay.mvstream.workers.dev](https://paypal-pay.mvstream.workers.dev)"
```

### 5. Simpan Kunci Rahasia JWT
```bash
wrangler secret put JWT_SECRET
# Masukkan string acak yang aman (minimal 32 karakter)
```

### 6. Jalankan Migrasi Database D1 SQL
Eksekusi file `schema.sql` untuk membuat tabel-tabel multi-tenant:

```bash
# Untuk testing lokal:
wrangler d1 execute store-db --local --file=./schema.sql

# Untuk deployment Cloudflare remote:
wrangler d1 execute store-db --remote --file=./schema.sql
```

### 7. Jalankan & Deploy
```bash
# Menjalankan di server development lokal
wrangler dev

# Deploy ke Cloudflare Edge Production
wrangler deploy
```

---

## 🛠️ Panduan Konfigurasi Midtrans per Tenant

Setiap merchant yang mendaftar dapat menghubungkan akun Midtrans miliknya dengan langkah berikut:

1. Merchant masuk ke Dashboard Toko.
2. Buka menu **Pengaturan Kredensial Midtrans**.
3. Masukkan `Client Key` dan `Server Key` dari [Midtrans Dashboard](https://dashboard.midtrans.com/) (Sandbox / Production).
4. Buka dashboard Midtrans merchant > Masuk ke **Settings** > **Configuration** > **Payment Notification URL**.
5. Salin URL Webhook dinamis yang disediakan oleh dashboard toko:
   ```text
   [https://domain-worker-anda.workers.dev/api/midtrans-webhook/](https://domain-worker-anda.workers.dev/api/midtrans-webhook/){storeId}
   ```
6. Simpan konfigurasi. Sekarang status pesanan pelanggan akan otomatis tersinkronisasi secara real-time.

---

## 📑 Dokumentasi Endpoint API

### 🔐 Autentikasi Merchant
| Method | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Mendaftarkan merchant baru beserta toko awalnya |
| `POST` | `/api/auth/login` | Otentikasi login merchant dan menghasilkan token JWT |

### ⚙️ Pengaturan Toko & Dynamic Schema
| Method | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/store/:storeId/schema` | Mengambil skema atribut dinamis toko |
| `POST` | `/api/store/:storeId/schema` | Mengubah/menambah atribut dinamis toko *(Auth Required)* |
| `POST` | `/api/store/:storeId/settings/midtrans` | Menyimpan Server Key & Client Key Midtrans toko *(Auth Required)* |

### 📦 Manajemen Produk & Belanja
| Method | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/store/:storeId/products` | Menampilkan seluruh produk toko beserta atribut dinamis |
| `POST` | `/api/store/:storeId/products` | Menambahkan produk baru ke toko *(Auth Required)* |
| `POST` | `/api/store/:storeId/checkout` | Memulai transaksi checkout menggunakan Snap Midtrans toko terkait |
| `POST` | `/api/midtrans-webhook/:storeId` | Callback notifikasi otomatis dari Midtrans per toko |

### 💳 SaaS Subscription (PayPal)
| Method | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `POST` | `/api/subscription/create-paypal-order` | Membuat pesanan langganan paket Pro/Enterprise |
| `POST` | `/api/subscription/capture-paypal` | Mengonfirmasi status capture pembayaran dari PayPal |

---

## 🔒 Keamanan & Verifikasi Signature

Sistem ini memverifikasi integritas setiap webhook Midtrans menggunakan algoritma **SHA-512**:
$$\text{Signature} = \text{SHA512}(\text{order\_id} + \text{status\_code} + \text{gross\_amount} + \text{MerchantServerKey})$$

Notifikasi dengan signature yang tidak valid akan langsung ditolak (`403 Forbidden`) untuk mencegah modifikasi status transaksi ilegal.

---

## 📄 Lisensi
Proyek ini didistribusikan di bawah lisensi **MIT**. Silakan gunakan, modifikasi, dan kembangkan sesuai kebutuhan platform bisnis Anda.