/**
 * ============================================================================
 * CLOUDFLARE WORKER MULTI-TENANT SAAS ENGINE
 * Fitur:
 * 1. Multi-Tenant Auth (Register, Login, JWT Token via Web Crypto)
 * 2. Sistem Langganan PayPal (Integrasi https://paypal-pay.mvstream.workers.dev)
 * 3. Dynamic Schema Builder per Toko (D1 + KV Cache)
 * 4. Katalog Produk Dinamis & Manajemen Inventaris
 * 5. Midtrans Payment Gateway per Tenant
 * 6. UI Dashboard & Storefront Web App (Bawaan)
 * ============================================================================
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// Definisi Environment Bindings Cloudflare
export interface Env {
  DB: D1Database;
  STORE_KV: KVNamespace;
  JWT_SECRET: string;
  PAYPAL_WORKER_URL?: string; // default: https://paypal-pay.mvstream.workers.dev
}

// Payload JWT User
interface JwtPayload {
  userId: string;
  email: string;
  role: string;
  exp: number;
}

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

/**
 * ============================================================================
 * HELPER KEAMANAN & KRIPTOGRAFI (WEB CRYPTO API)
 * ============================================================================
 */

// Hash Password dengan PBKDF2 (Native Cloudflare Worker)
async function hashPassword(password: string, saltHex?: string): Promise<{ hashHex: string; saltHex: string }> {
  const enc = new TextEncoder();
  const salt = saltHex 
    ? new Uint8Array(saltHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)))
    : crypto.getRandomValues(new Uint8Array(16));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const newSaltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  return { hashHex, saltHex: newSaltHex };
}

// Generate JWT Token
async function createJWT(payload: Omit<JwtPayload, 'exp'>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60); // 7 Hari masa berlaku
  const fullPayload: JwtPayload = { ...payload, exp };

  const encodeBase64Url = (obj: any) =>
    btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  const unsignedToken = `${encodeBase64Url(header)}.${encodeBase64Url(fullPayload)}`;
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret || 'default-super-secret-key-32chars!!'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(unsignedToken));
  const signatureBase64Url = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${unsignedToken}.${signatureBase64Url}`;
}

// Verifikasi JWT Middleware
async function authMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ success: false, error: 'Token otentikasi tidak ditemukan' }, 401);
  }

  const token = authHeader.split(' ')[1];
  const parts = token.split('.');
  if (parts.length !== 3) {
    return c.json({ success: false, error: 'Format token tidak valid' }, 401);
  }

  try {
    const secret = c.env.JWT_SECRET || 'default-super-secret-key-32chars!!';
    const enc = new TextEncoder();
    const unsignedToken = `${parts[0]}.${parts[1]}`;

    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const binarySignature = Uint8Array.from(
      atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
      char => char.charCodeAt(0)
    );

    const isValid = await crypto.subtle.verify('HMAC', key, binarySignature, enc.encode(unsignedToken));
    if (!isValid) return c.json({ success: false, error: 'Signature token tidak sah' }, 401);

    const payload: JwtPayload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return c.json({ success: false, error: 'Sesi token telah kedaluwarsa' }, 401);
    }

    c.set('user', payload);
    await next();
  } catch (err: any) {
    return c.json({ success: false, error: 'Otorisasi gagal: ' + err.message }, 401);
  }
}

/**
 * ============================================================================
 * 1. AUTHENTICATION (REGISTER, LOGIN, PROFILE)
 * ============================================================================
 */

// POST: Registrasi Pemilik Toko Baru
app.post('/api/auth/register', async (c) => {
  try {
    const { name, email, password, storeName } = await c.req.json();
    if (!name || !email || !password || !storeName) {
      return c.json({ success: false, error: 'Semua kolom pendaftaran wajib diisi' }, 400);
    }

    // Cek apakah email sudah terdaftar
    const existingUser = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existingUser) {
      return c.json({ success: false, error: 'Email sudah terdaftar. Silakan login.' }, 400);
    }

    const { hashHex, saltHex } = await hashPassword(password);
    const userId = 'USR-' + crypto.randomUUID().slice(0, 8);
    const storeId = 'STORE-' + crypto.randomUUID().slice(0, 8);
    const storeSlug = storeName.toLowerCase().replace(/[^a-z0-9]/g, '-');

    // Buat User & Toko Awal dalam 1 Batch D1
    await c.env.DB.batch([
      c.env.DB.prepare(
        'INSERT INTO users (id, name, email, password_hash, salt) VALUES (?, ?, ?, ?, ?)'
      ).bind(userId, name, email, hashHex, saltHex),
      c.env.DB.prepare(
        'INSERT INTO stores (id, user_id, name, slug, plan, status) VALUES (?, ?, ?, ?, "FREE", "ACTIVE")'
      ).bind(storeId, userId, storeName, storeSlug),
      // Inisialisasi default dynamic schema untuk toko baru
      c.env.DB.prepare(
        'INSERT INTO store_schemas (store_id, schema_json, is_active) VALUES (?, ?, 1)'
      ).bind(
        storeId,
        JSON.stringify([
          { id: 'ukuran', label: 'Ukuran Produk', type: 'select', options: ['S', 'M', 'L', 'XL'], filterable: true, required: true },
          { id: 'warna', label: 'Warna', type: 'color', filterable: true, required: false }
        ])
      )
    ]);

    const token = await createJWT({ userId, email, role: 'merchant' }, c.env.JWT_SECRET);

    return c.json({
      success: true,
      message: 'Registrasi berhasil! Toko Anda siap digunakan.',
      token,
      store: { id: storeId, name: storeName, slug: storeSlug, plan: 'FREE' }
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

// POST: Login Pemilik Toko
app.post('/api/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json();
    const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<any>();

    if (!user) {
      return c.json({ success: false, error: 'Email atau password salah' }, 401);
    }

    const { hashHex } = await hashPassword(password, user.salt);
    if (hashHex !== user.password_hash) {
      return c.json({ success: false, error: 'Email atau password salah' }, 401);
    }

    // Ambil data toko milik user
    const store = await c.env.DB.prepare('SELECT * FROM stores WHERE user_id = ? LIMIT 1').bind(user.id).first<any>();
    const token = await createJWT({ userId: user.id, email: user.email, role: 'merchant' }, c.env.JWT_SECRET);

    return c.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email },
      store: store ? {
        id: store.id,
        name: store.name,
        slug: store.slug,
        plan: store.plan,
        midtransClientKey: store.midtrans_client_key
      } : null
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 2. SUBSCRIPTION SYSTEM (INTEGRASI PAYPAL WORKER)
 * Endpoint Target: https://paypal-pay.mvstream.workers.dev
 * ============================================================================
 */

// POST: Buat Invoice / Order Langganan PayPal
app.post('/api/subscription/create-paypal-order', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const { plan, durationMonths } = await c.req.json(); // plan: 'PRO' | 'ENTERPRISE'
    const paypalWorkerUrl = c.env.PAYPAL_WORKER_URL || 'https://paypal-pay.mvstream.workers.dev';

    // Penentuan Harga Langganan
    const priceMap: Record<string, number> = {
      'PRO': 15.00,        // $15 / Bulan
      'ENTERPRISE': 49.00  // $49 / Bulan
    };

    const amount = (priceMap[plan] || 15.00) * (durationMonths || 1);
    const store = await c.env.DB.prepare('SELECT id, name FROM stores WHERE user_id = ?').bind(user.userId).first<any>();

    // Panggil Service Worker PayPal
    const paypalResponse = await fetch(`${paypalWorkerUrl}/api/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: amount.toFixed(2),
        currency: 'USD',
        description: `Langganan Paket ${plan} Toko ${store?.name || 'SaaS'} (${durationMonths || 1} Bulan)`,
        customId: JSON.stringify({ userId: user.userId, storeId: store?.id, plan, durationMonths })
      })
    });

    const paypalData = await paypalResponse.json<any>();

    return c.json({
      success: true,
      message: 'Order PayPal berhasil dibuat',
      orderId: paypalData.orderId || paypalData.id,
      approvalUrl: paypalData.approvalUrl || paypalData.links?.find((l: any) => l.rel === 'approve')?.href,
      plan,
      amount
    });
  } catch (err: any) {
    return c.json({ success: false, error: 'Gagal menghubungkan ke PayPal Worker: ' + err.message }, 500);
  }
});

// POST: Konfirmasi / Webhook Sukses Pembayaran PayPal
app.post('/api/subscription/capture-paypal', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const { paypalOrderId, plan } = await c.req.json();
    const paypalWorkerUrl = c.env.PAYPAL_WORKER_URL || 'https://paypal-pay.mvstream.workers.dev';

    // Verifikasi Capture dengan PayPal Worker
    const captureRes = await fetch(`${paypalWorkerUrl}/api/capture-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orderId: paypalOrderId })
    });

    const captureData = await captureRes.json<any>();

    // Update status paket toko menjadi PRO / ENTERPRISE di Cloudflare D1
    await c.env.DB.prepare(
      'UPDATE stores SET plan = ?, status = "ACTIVE" WHERE user_id = ?'
    ).bind(plan || 'PRO', user.userId).run();

    // Catat riwayat subscription
    await c.env.DB.prepare(
      `INSERT INTO subscriptions (id, user_id, plan, amount, paypal_order_id, status)
       VALUES (?, ?, ?, ?, ?, "PAID")`
    ).bind(
      'SUB-' + crypto.randomUUID().slice(0, 8),
      user.userId,
      plan || 'PRO',
      captureData.amount || 15.00,
      paypalOrderId
    ).run();

    return c.json({
      success: true,
      message: `Selamat! Toko Anda kini telah aktif pada paket ${plan || 'PRO'}.`,
      plan: plan || 'PRO'
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 3. MULTI-TENANT DYNAMIC SCHEMA BUILDER (ISOLASI PER TOKO)
 * ============================================================================
 */

// GET: Ambil Dynamic Schema Toko
app.get('/api/store/:storeId/schema', async (c) => {
  const storeId = c.req.param('storeId');
  const cacheKey = `schema:${storeId}`;

  // Cek KV Cache Toko
  const cached = await c.env.STORE_KV.get(cacheKey);
  if (cached) return c.json({ success: true, source: 'kv', data: JSON.parse(cached) });

  const record = await c.env.DB.prepare(
    'SELECT schema_json FROM store_schemas WHERE store_id = ? AND is_active = 1 LIMIT 1'
  ).bind(storeId).first<{ schema_json: string }>();

  const schema = record ? JSON.parse(record.schema_json) : [];
  await c.env.STORE_KV.put(cacheKey, JSON.stringify(schema), { expirationTtl: 3600 });

  return c.json({ success: true, source: 'd1', data: schema });
});

// POST: Update Dynamic Schema Toko (Wajib Login & Pemilik Toko)
app.post('/api/store/:storeId/schema', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const newSchema = await c.req.json();

  // Validasi Kepemilikan Toko & Kuota Fitur berdasarkan Paket
  const store = await c.env.DB.prepare('SELECT * FROM stores WHERE id = ? AND user_id = ?').bind(storeId, user.userId).first<any>();
  if (!store) {
    return c.json({ success: false, error: 'Akses ditolak: Toko tidak ditemukan' }, 403);
  }

  // Cek Batasan Paket FREE
  if (store.plan === 'FREE' && Array.isArray(newSchema) && newSchema.length > 3) {
    return c.json({
      success: false,
      error: 'Paket FREE dibatasi maksimal 3 atribut dinamis. Upgrade ke PRO via PayPal untuk atribut tanpa batas!'
    }, 403);
  }

  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE store_schemas SET is_active = 0 WHERE store_id = ?').bind(storeId),
    c.env.DB.prepare('INSERT INTO store_schemas (store_id, schema_json, is_active) VALUES (?, ?, 1)').bind(storeId, JSON.stringify(newSchema))
  ]);

  // Update Cache KV
  await c.env.STORE_KV.put(`schema:${storeId}`, JSON.stringify(newSchema));

  return c.json({ success: true, message: 'Skema toko berhasil diperbarui!' });
});

// POST: Konfigurasi Kunci Midtrans Toko
app.post('/api/store/:storeId/settings/midtrans', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const { serverKey, clientKey } = await c.req.json();

  await c.env.DB.prepare(
    'UPDATE stores SET midtrans_server_key = ?, midtrans_client_key = ? WHERE id = ? AND user_id = ?'
  ).bind(serverKey, clientKey, storeId, user.userId).run();

  return c.json({ success: true, message: 'Kredensial Midtrans toko berhasil disimpan!' });
});

/**
 * ============================================================================
 * 4. PRODUK & MIDTRANS CHECKOUT PER TENANT
 * ============================================================================
 */

// GET: Katalog Produk Toko
app.get('/api/store/:storeId/products', async (c) => {
  const storeId = c.req.param('storeId');
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM products WHERE store_id = ? ORDER BY created_at DESC'
  ).bind(storeId).all();

  const products = results.map((row: any) => ({
    id: row.id,
    name: row.name,
    price: row.price,
    stock: row.stock,
    imageUrl: row.image_url,
    attributes: JSON.parse(row.attributes_json || '{}')
  }));

  return c.json({ success: true, data: products });
});

// POST: Tambah Produk Baru ke Toko
app.post('/api/store/:storeId/products', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const { name, price, stock, imageUrl, attributes } = await c.req.json();

  const store = await c.env.DB.prepare('SELECT plan FROM stores WHERE id = ? AND user_id = ?').bind(storeId, user.userId).first<any>();
  if (!store) return c.json({ success: false, error: 'Toko tidak sah' }, 403);

  const prodId = 'PROD-' + crypto.randomUUID().slice(0, 8);
  await c.env.DB.prepare(
    'INSERT INTO products (id, store_id, name, price, stock, image_url, attributes_json) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(prodId, storeId, name, price, stock, imageUrl || '', JSON.stringify(attributes || {})).run();

  return c.json({ success: true, message: 'Produk berhasil ditambahkan', productId: prodId });
});

// POST: Checkout Midtrans Snap Khusus Toko
app.post('/api/store/:storeId/checkout', async (c) => {
  const storeId = c.req.param('storeId');
  const { customer, items, totalAmount } = await c.req.json();

  const store = await c.env.DB.prepare('SELECT * FROM stores WHERE id = ?').bind(storeId).first<any>();
  if (!store || !store.midtrans_server_key) {
    return c.json({ success: false, error: 'Toko belum mengatur Server Key Midtrans' }, 400);
  }

  const orderId = `ORD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
  const authHeader = 'Basic ' + btoa(store.midtrans_server_key + ':');

  const midtransRes = await fetch('https://app.sandbox.midtrans.com/snap/v1/transactions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': authHeader
    },
    body: JSON.stringify({
      transaction_details: { order_id: orderId, gross_amount: totalAmount },
      customer_details: customer,
      item_details: items
    })
  });

  const snapData = await midtransRes.json<any>();

  await c.env.DB.prepare(
    'INSERT INTO orders (id, store_id, customer_name, customer_email, total_amount, status, snap_token, items_json) VALUES (?, ?, ?, ?, ?, "pending", ?, ?)'
  ).bind(orderId, storeId, customer.name, customer.email, totalAmount, snapData.token, JSON.stringify(items)).run();

  return c.json({ success: true, orderId, snapToken: snapData.token, redirectUrl: snapData.redirect_url });
});

/**
 * ============================================================================
 * 5. FRONTEND SAAS LANDING & DASHBOARD SPA (DIRECTLY HOSTED BY WORKER)
 * ============================================================================
 */
app.get('/', (c) => {
  return c.html(`
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Multi-Tenant E-Commerce & Subscription Engine</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <!-- Navigasi Utama -->
  <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-xl bg-orange-500 flex items-center justify-center font-bold text-white shadow-lg shadow-orange-500/20">⚡</div>
        <span class="font-bold text-lg text-white">StoreEngine <span class="text-xs bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded border border-orange-500/30">SaaS Multi-Tenant</span></span>
      </div>
      <div id="auth-nav" class="flex items-center gap-3">
        <!-- Status auth dynamically injected -->
      </div>
    </div>
  </header>

  <!-- Main View Container -->
  <main class="max-w-7xl mx-auto px-4 py-8">
    <div id="app-view"></div>
  </main>

  <script>
    let currentUser = null;
    let currentStore = null;
    let authToken = localStorage.getItem('token');

    document.addEventListener('DOMContentLoaded', () => {
      initApp();
    });

    function initApp() {
      if (authToken) {
        renderDashboard();
      } else {
        renderLandingAndAuth();
      }
    }

    function renderLandingAndAuth() {
      const nav = document.getElementById('auth-nav');
      nav.innerHTML = '<button onclick="showAuthModal(\\'login\\')" class="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl">Masuk</button><button onclick="showAuthModal(\\'register\\')" class="px-4 py-2 text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-white rounded-xl shadow-lg shadow-orange-500/20">Daftar Toko</button>';

      document.getElementById('app-view').innerHTML = \`
        <div class="text-center max-w-3xl mx-auto py-12 space-y-6">
          <span class="px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">Cloudflare Edge + D1 + Midtrans + PayPal</span>
          <h1 class="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">Platform Toko E-Commerce dengan <span class="text-orange-400">Skema Atribut Dinamis</span></h1>
          <p class="text-slate-400 text-sm leading-relaxed">Kelola toko Anda dengan skema produk fleksibel tanpa batas. Dukungan gateway pembayaran Midtrans Snap untuk pelanggan lokal dan sistem langganan PayPal untuk merchant global.</p>
          <div class="flex justify-center gap-4 pt-4">
            <button onclick="showAuthModal('register')" class="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-white font-bold rounded-xl text-sm shadow-xl shadow-orange-500/25">Mulai Buka Toko Gratis &rarr;</button>
          </div>
        </div>

        <!-- Tabel Paket Langganan PayPal -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto pt-8">
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 class="text-lg font-bold text-white">Starter (Free)</h3>
            <p class="text-2xl font-black text-white">Rp 0 <span class="text-xs font-normal text-slate-400">/ selamanya</span></p>
            <ul class="text-xs text-slate-300 space-y-2">
              <li>✓ Maksimal 3 Field Dinamis</li>
              <li>✓ 20 Produk Aktif</li>
              <li>✓ Integrasi Midtrans Snap</li>
            </ul>
          </div>
          <div class="bg-slate-900 border-2 border-orange-500 rounded-2xl p-6 space-y-4 relative shadow-2xl shadow-orange-500/10">
            <span class="absolute -top-3 right-4 px-2 py-0.5 bg-orange-500 text-[10px] font-bold uppercase rounded text-white">Paling Populer</span>
            <h3 class="text-lg font-bold text-white">Pro Merchant</h3>
            <p class="text-2xl font-black text-orange-400">$15 <span class="text-xs font-normal text-slate-400">/ bulan (via PayPal)</span></p>
            <ul class="text-xs text-slate-300 space-y-2">
              <li>✓ <strong>Unlimited Dynamic Schema</strong></li>
              <li>✓ Unlimited Produk & Transaksi</li>
              <li>✓ Fast Edge KV Caching</li>
            </ul>
            <button onclick="subscribePayPal('PRO')" class="w-full py-2 bg-orange-500 hover:bg-orange-600 text-white font-bold text-xs rounded-xl">Langganan via PayPal</button>
          </div>
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
            <h3 class="text-lg font-bold text-white">Enterprise</h3>
            <p class="text-2xl font-black text-white">$49 <span class="text-xs font-normal text-slate-400">/ bulan (via PayPal)</span></p>
            <ul class="text-xs text-slate-300 space-y-2">
              <li>✓ Semua Fitur Pro</li>
              <li>✓ Custom Domain & R2 Bucket Terdedikasi</li>
              <li>✓ Prioritas SLA 99.99%</li>
            </ul>
            <button onclick="subscribePayPal('ENTERPRISE')" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs rounded-xl">Langganan via PayPal</button>
          </div>
        </div>
      \`;
    }

    function showAuthModal(type) {
      const email = prompt("Masukkan Email:");
      const password = prompt("Masukkan Password:");
      if (!email || !password) return;

      if (type === 'register') {
        const name = prompt("Nama Anda:");
        const storeName = prompt("Nama Toko:");
        fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password, storeName })
        }).then(r => r.json()).then(res => {
          if (res.success) {
            localStorage.setItem('token', res.token);
            authToken = res.token;
            location.reload();
          } else {
            alert(res.error);
          }
        });
      } else {
        fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        }).then(r => r.json()).then(res => {
          if (res.success) {
            localStorage.setItem('token', res.token);
            authToken = res.token;
            location.reload();
          } else {
            alert(res.error);
          }
        });
      }
    }

    function subscribePayPal(plan) {
      if (!authToken) {
        alert("Silakan login terlebih dahulu untuk berlangganan!");
        showAuthModal('login');
        return;
      }
      fetch('/api/subscription/create-paypal-order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken },
        body: JSON.stringify({ plan, durationMonths: 1 })
      }).then(r => r.json()).then(res => {
        if (res.success && res.approvalUrl) {
          window.open(res.approvalUrl, '_blank');
        } else {
          alert(res.error || 'Gagal membuat order PayPal');
        }
      });
    }

    function renderDashboard() {
      const nav = document.getElementById('auth-nav');
      nav.innerHTML = '<button onclick="logout()" class="px-4 py-2 text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl hover:bg-red-500/30">Keluar</button>';

      document.getElementById('app-view').innerHTML = \`
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
          <div class="flex justify-between items-center pb-4 border-b border-slate-800">
            <div>
              <h2 class="text-xl font-bold text-white">Merchant Dashboard</h2>
              <p class="text-xs text-slate-400">Atur Skema Atribut Dinamis, Produk, dan Integrasi Midtrans Toko Anda.</p>
            </div>
            <button onclick="subscribePayPal('PRO')" class="px-4 py-2 bg-gradient-to-r from-amber-500 to-orange-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-orange-500/20">⭐ Upgrade Paket Toko via PayPal</button>
          </div>
          <p class="text-sm text-slate-300">Sistem SaaS Multi-Tenant siap digunakan di Cloudflare Workers!</p>
        </div>
      \`;
    }

    function logout() {
      localStorage.removeItem('token');
      location.reload();
    }
  </script>
</body>
</html>
  `);
});

export default app;