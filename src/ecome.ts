/**
 * ============================================================================
 * CLOUDFLARE WORKER MULTI-TENANT DYNAMIC E-COMMERCE & MIDTRANS ENGINE
 * Fitur:
 * 1. Multi-Tenant Auth & Dashboard SPA Terintegrasi
 * 2. Dinamis Midtrans Gateway (Client Key & Server Key per Tenant/Toko)
 * 3. Dinamis Webhook Notification URL per Tenant (/api/midtrans-webhook/:storeId)
 * 4. Dynamic Product Schema Builder (D1 + KV Cache)
 * 5. Langganan SaaS PayPal (https://paypal-pay.mvstream.workers.dev)
 * ============================================================================
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

export interface Env {
  DB: D1Database;
  STORE_KV: KVNamespace;
  JWT_SECRET: string;
  PAYPAL_WORKER_URL?: string;
}

interface JwtPayload {
  userId: string;
  email: string;
  role: string;
  exp: number;
}

const app = new Hono<{ Bindings: Env }>();

// Middleware CORS
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

/**
 * ============================================================================
 * HELPER KEAMANAN & KRIPTOGRAFI (PBKDF2 & JWT NATIVE CLOUDFLARE)
 * ============================================================================
 */

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
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );

  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const newSaltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');

  return { hashHex, saltHex: newSaltHex };
}

async function createJWT(payload: Omit<JwtPayload, 'exp'>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60);
  const fullPayload: JwtPayload = { ...payload, exp };

  const encodeBase64Url = (obj: any) =>
    btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  const unsignedToken = `${encodeBase64Url(header)}.${encodeBase64Url(fullPayload)}`;
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret || 'default-jwt-secret-key-32chars-min!'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(unsignedToken));
  const signatureBase64Url = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${unsignedToken}.${signatureBase64Url}`;
}

async function authMiddleware(c: any, next: any) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ success: false, error: 'Token otentikasi tidak ditemukan' }, 401);
  }

  const token = authHeader.split(' ')[1];
  const parts = token.split('.');
  if (parts.length !== 3) {
    return c.json({ success: false, error: 'Format token salah' }, 401);
  }

  try {
    const secret = c.env.JWT_SECRET || 'default-jwt-secret-key-32chars-min!';
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
 * 1. AUTHENTICATION & MULTI-TENANT ONBOARDING
 * ============================================================================
 */

app.post('/api/auth/register', async (c) => {
  try {
    const { name, email, password, storeName } = await c.req.json();
    if (!name || !email || !password || !storeName) {
      return c.json({ success: false, error: 'Lengkapi semua kolom formulir' }, 400);
    }

    const existingUser = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existingUser) {
      return c.json({ success: false, error: 'Email sudah terdaftar' }, 400);
    }

    const { hashHex, saltHex } = await hashPassword(password);
    const userId = 'USR-' + crypto.randomUUID().slice(0, 8);
    const storeId = 'STORE-' + crypto.randomUUID().slice(0, 8);
    const storeSlug = storeName.toLowerCase().replace(/[^a-z0-9]/g, '-');

    await c.env.DB.batch([
      c.env.DB.prepare(
        'INSERT INTO users (id, name, email, password_hash, salt) VALUES (?, ?, ?, ?, ?)'
      ).bind(userId, name, email, hashHex, saltHex),
      c.env.DB.prepare(
        'INSERT INTO stores (id, user_id, name, slug, plan, midtrans_is_prod) VALUES (?, ?, ?, ?, "FREE", 0)'
      ).bind(storeId, userId, storeName, storeSlug),
      c.env.DB.prepare(
        'INSERT INTO store_schemas (store_id, schema_json, is_active) VALUES (?, ?, 1)'
      ).bind(
        storeId,
        JSON.stringify([
          { id: 'ukuran', label: 'Ukuran Produk', type: 'select', options: ['S', 'M', 'L', 'XL'], filterable: true, required: true },
          { id: 'warna', label: 'Warna Pilihan', type: 'color', filterable: true, required: false }
        ])
      )
    ]);

    const token = await createJWT({ userId, email, role: 'merchant' }, c.env.JWT_SECRET);

    return c.json({
      success: true,
      message: 'Toko berhasil dibuat!',
      token,
      store: { id: storeId, name: storeName, slug: storeSlug, plan: 'FREE' }
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

app.post('/api/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json();
    const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<any>();

    if (!user) return c.json({ success: false, error: 'Email atau password salah' }, 401);

    const { hashHex } = await hashPassword(password, user.salt);
    if (hashHex !== user.password_hash) return c.json({ success: false, error: 'Email atau password salah' }, 401);

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
        midtransClientKey: store.midtrans_client_key || '',
        midtransIsProd: Boolean(store.midtrans_is_prod)
      } : null
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 2. TENANT MIDTRANS CONFIGURATION & SETTINGS
 * ============================================================================
 */

// POST: Simpan Kredensial Midtrans Toko Mandiri (Server Key & Client Key)
app.post('/api/store/:storeId/settings/midtrans', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const storeId = c.req.param('storeId');
    const { serverKey, clientKey, isProduction } = await c.req.json();

    if (!serverKey || !clientKey) {
      return c.json({ success: false, error: 'Server Key dan Client Key Midtrans wajib diisi' }, 400);
    }

    // Validasi Kepemilikan Toko
    const store = await c.env.DB.prepare('SELECT id FROM stores WHERE id = ? AND user_id = ?')
      .bind(storeId, user.userId)
      .first();

    if (!store) return c.json({ success: false, error: 'Akses ditolak' }, 403);

    // Update data di D1
    await c.env.DB.prepare(
      'UPDATE stores SET midtrans_server_key = ?, midtrans_client_key = ?, midtrans_is_prod = ? WHERE id = ?'
    ).bind(serverKey, clientKey, isProduction ? 1 : 0, storeId).run();

    // Invalidate KV Cache toko jika ada
    await c.env.STORE_KV.delete(`store_meta:${storeId}`);

    return c.json({
      success: true,
      message: 'Kredensial Midtrans toko berhasil disimpan dan aktif!',
      webhookUrl: `/api/midtrans-webhook/${storeId}`
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 3. DYNAMIC SCHEMA MANAGEMENT PER TENANT
 * ============================================================================
 */

// GET: Schema Atribut Toko
app.get('/api/store/:storeId/schema', async (c) => {
  const storeId = c.req.param('storeId');
  const cacheKey = `schema:${storeId}`;

  const cached = await c.env.STORE_KV.get(cacheKey);
  if (cached) return c.json({ success: true, source: 'kv', data: JSON.parse(cached) });

  const record = await c.env.DB.prepare(
    'SELECT schema_json FROM store_schemas WHERE store_id = ? AND is_active = 1 LIMIT 1'
  ).bind(storeId).first<{ schema_json: string }>();

  const schema = record ? JSON.parse(record.schema_json) : [];
  await c.env.STORE_KV.put(cacheKey, JSON.stringify(schema), { expirationTtl: 3600 });

  return c.json({ success: true, source: 'd1', data: schema });
});

// POST: Update Schema Atribut Toko
app.post('/api/store/:storeId/schema', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const newSchema = await c.req.json();

  const store = await c.env.DB.prepare('SELECT plan FROM stores WHERE id = ? AND user_id = ?')
    .bind(storeId, user.userId)
    .first<any>();

  if (!store) return c.json({ success: false, error: 'Toko tidak ditemukan' }, 403);

  // Pembatasan Paket FREE
  if (store.plan === 'FREE' && Array.isArray(newSchema) && newSchema.length > 3) {
    return c.json({
      success: false,
      error: 'Paket FREE dibatasi 3 atribut dinamis. Upgrade ke PRO via PayPal untuk kuota tanpa batas!'
    }, 403);
  }

  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE store_schemas SET is_active = 0 WHERE store_id = ?').bind(storeId),
    c.env.DB.prepare('INSERT INTO store_schemas (store_id, schema_json, is_active) VALUES (?, ?, 1)').bind(storeId, JSON.stringify(newSchema))
  ]);

  await c.env.STORE_KV.put(`schema:${storeId}`, JSON.stringify(newSchema));

  return c.json({ success: true, message: 'Skema dinamis toko berhasil diperbarui!' });
});

/**
 * ============================================================================
 * 4. PRODUK & TRANSAKSI MIDTRANS DINAMIS PER TENANT
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

// POST: Tambah Produk Baru
app.post('/api/store/:storeId/products', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const { name, price, stock, imageUrl, attributes } = await c.req.json();

  const store = await c.env.DB.prepare('SELECT id FROM stores WHERE id = ? AND user_id = ?')
    .bind(storeId, user.userId)
    .first();

  if (!store) return c.json({ success: false, error: 'Akses ditolak' }, 403);

  const prodId = 'PROD-' + crypto.randomUUID().slice(0, 8);
  await c.env.DB.prepare(
    'INSERT INTO products (id, store_id, name, price, stock, image_url, attributes_json) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(prodId, storeId, name, price, stock, imageUrl || '', JSON.stringify(attributes || {})).run();

  return c.json({ success: true, message: 'Produk berhasil ditambahkan', productId: prodId });
});

// POST: Checkout Midtrans Menggunakan Kredensial Toko Terkait
app.post('/api/store/:storeId/checkout', async (c) => {
  try {
    const storeId = c.req.param('storeId');
    const { customer, items, totalAmount } = await c.req.json();

    // 1. Ambil Kunci Midtrans Toko dari Database D1
    const store = await c.env.DB.prepare(
      'SELECT id, name, midtrans_server_key, midtrans_is_prod FROM stores WHERE id = ?'
    ).bind(storeId).first<any>();

    if (!store || !store.midtrans_server_key) {
      return c.json({
        success: false,
        error: 'Toko ini belum menyelesaikan konfigurasi Server Key Midtrans di dashboard merchant'
      }, 400);
    }

    const orderId = `ORD-${store.id.slice(-4)}-${Date.now()}`;
    const baseUrl = store.midtrans_is_prod 
      ? 'https://app.midtrans.com/snap/v1' 
      : 'https://app.sandbox.midtrans.com/snap/v1';

    // 2. Request Snap Token ke Akun Midtrans Toko Terkait
    const authHeader = 'Basic ' + btoa(store.midtrans_server_key + ':');
    const midtransRes = await fetch(`${baseUrl}/transactions`, {
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

    if (!midtransRes.ok) {
      return c.json({ success: false, error: 'Gagal membuat transaksi Midtrans', details: snapData }, 502);
    }

    // 3. Simpan Pesanan ke D1
    await c.env.DB.prepare(
      'INSERT INTO orders (id, store_id, customer_name, customer_email, total_amount, status, snap_token, items_json) VALUES (?, ?, ?, ?, ?, "pending", ?, ?)'
    ).bind(orderId, storeId, customer.name, customer.email, totalAmount, snapData.token, JSON.stringify(items)).run();

    return c.json({
      success: true,
      orderId,
      snapToken: snapData.token,
      redirectUrl: snapData.redirect_url
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

// POST: Midtrans Webhook Callback Dinamis per Toko (/api/midtrans-webhook/:storeId)
app.post('/api/midtrans-webhook/:storeId', async (c) => {
  try {
    const storeId = c.req.param('storeId');
    const payload = await c.req.json();
    const { order_id, status_code, gross_amount, signature_key, transaction_status, fraud_status } = payload;

    // Ambil Server Key Toko Terkait
    const store = await c.env.DB.prepare('SELECT midtrans_server_key FROM stores WHERE id = ?')
      .bind(storeId)
      .first<any>();

    if (!store || !store.midtrans_server_key) {
      return c.json({ error: 'Toko tidak ditemukan' }, 404);
    }

    // Verifikasi Signature SHA-512 dengan Server Key Toko
    const rawString = `${order_id}${status_code}${gross_amount}${store.midtrans_server_key}`;
    const encoder = new TextEncoder();
    const data = encoder.encode(rawString);
    const hashBuffer = await crypto.subtle.digest('SHA-512', data);
    const computedSignature = Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (computedSignature !== signature_key) {
      return c.json({ error: 'Invalid Signature' }, 403);
    }

    // Tentukan status pembayaran
    let orderStatus = 'pending';
    if (transaction_status === 'capture') {
      orderStatus = fraud_status === 'accept' ? 'paid' : 'challenge';
    } else if (transaction_status === 'settlement') {
      orderStatus = 'paid';
    } else if (['cancel', 'deny', 'expire'].includes(transaction_status)) {
      orderStatus = 'failed';
    }

    // Update status di D1 & kurangi stok jika status 'paid'
    if (orderStatus === 'paid') {
      const order = await c.env.DB.prepare('SELECT items_json, status FROM orders WHERE id = ? AND store_id = ?')
        .bind(order_id, storeId)
        .first<{ items_json: string; status: string }>();

      if (order && order.status !== 'paid') {
        const items = JSON.parse(order.items_json);
        const batchOps = [
          c.env.DB.prepare("UPDATE orders SET status = 'paid' WHERE id = ?").bind(order_id)
        ];

        for (const item of items) {
          if (item.productId) {
            batchOps.push(
              c.env.DB.prepare('UPDATE products SET stock = MAX(0, stock - ?) WHERE id = ?').bind(item.quantity || 1, item.productId)
            );
          }
        }
        await c.env.DB.batch(batchOps);
      }
    } else {
      await c.env.DB.prepare('UPDATE orders SET status = ? WHERE id = ?').bind(orderStatus, order_id).run();
    }

    return c.json({ status: 'ok', message: `Pesanan ${order_id} diperbarui menjadi ${orderStatus}` });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 5. SAAS SUBSCRIPTION (INTEGRASI PAYPAL WORKER)
 * ============================================================================
 */

app.post('/api/subscription/create-paypal-order', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const { plan } = await c.req.json();
    const paypalWorkerUrl = c.env.PAYPAL_WORKER_URL || 'https://paypal-pay.mvstream.workers.dev';

    const priceMap: Record<string, number> = { 'PRO': 15.00, 'ENTERPRISE': 49.00 };
    const amount = priceMap[plan] || 15.00;

    const paypalResponse = await fetch(`${paypalWorkerUrl}/api/create-order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: amount.toFixed(2),
        currency: 'USD',
        description: `Langganan SaaS Paket ${plan}`,
        customId: JSON.stringify({ userId: user.userId, plan })
      })
    });

    const paypalData = await paypalResponse.json<any>();
    return c.json({
      success: true,
      approvalUrl: paypalData.approvalUrl || paypalData.links?.find((l: any) => l.rel === 'approve')?.href,
      plan,
      amount
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

/**
 * ============================================================================
 * 6. DASHBOARD & STOREFRONT SPA (DIHOSTING LANGSUNG OLEH WORKER)
 * ============================================================================
 */
app.get('*', (c) => {
  return c.html(`
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Store Engine - SaaS Multi-Tenant</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
    body { font-family: 'Plus Jakarta Sans', sans-serif; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col">

  <!-- Header Global -->
  <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-orange-500 to-amber-500 flex items-center justify-center font-bold text-white shadow-lg shadow-orange-500/20">⚡</div>
        <div>
          <span class="font-bold text-white leading-tight block">StoreEngine SaaS</span>
          <span class="text-[10px] text-orange-400 font-mono">Dinamis Midtrans per Toko</span>
        </div>
      </div>
      <div id="nav-actions" class="flex items-center gap-3"></div>
    </div>
  </header>

  <!-- Container Konten Utama -->
  <main class="flex-grow max-w-7xl w-full mx-auto px-4 py-8" id="app-root"></main>

  <script>
    let token = localStorage.getItem('token');
    let userStore = JSON.parse(localStorage.getItem('store') || 'null');

    document.addEventListener('DOMContentLoaded', () => {
      renderApp();
    });

    function renderApp() {
      const nav = document.getElementById('nav-actions');
      const root = document.getElementById('app-root');

      if (!token) {
        // Tampilan Landing Page & Login
        nav.innerHTML = \`
          <button onclick="promptLogin()" class="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl">Masuk Merchant</button>
          <button onclick="promptRegister()" class="px-4 py-2 text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-white rounded-xl shadow-lg shadow-orange-500/20">Buka Toko Baru</button>
        \`;

        root.innerHTML = \`
          <div class="text-center max-w-3xl mx-auto py-12 space-y-6">
            <span class="px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">Dukungan Multi-Tenant Midtrans + Skema Dinamis</span>
            <h1 class="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">Platform E-Commerce Modern dengan <span class="text-orange-400">Midtrans Mandiri</span></h1>
            <p class="text-slate-400 text-sm leading-relaxed">Setiap pemilik toko dapat memasukkan Server Key & Client Key Midtrans milik masing-masing. Dana penjualan langsung masuk ke rekening toko Anda tanpa potongan platform.</p>
            <div class="flex justify-center gap-4 pt-4">
              <button onclick="promptRegister()" class="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-white font-bold rounded-xl text-sm shadow-xl shadow-orange-500/25">Mulai Buka Toko Sekarang &rarr;</button>
            </div>
          </div>
        \`;
      } else {
        // Tampilan Dashboard Toko Tenant
        nav.innerHTML = \`
          <span class="text-xs text-slate-400">Toko: <strong class="text-white">\${userStore?.name || 'Toko Saya'}</strong> (\${userStore?.plan || 'FREE'})</span>
          <button onclick="logout()" class="px-3 py-1.5 text-xs bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl hover:bg-red-500/30">Keluar</button>
        \`;

        root.innerHTML = \`
          <div class="space-y-6">
            <!-- Kartu Konfigurasi Midtrans Tenant -->
            <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div class="flex items-center justify-between pb-3 border-b border-slate-800">
                <div>
                  <h2 class="text-lg font-bold text-white flex items-center gap-2">
                    <i data-lucide="credit-card" class="w-5 h-5 text-orange-400"></i> Pengaturan Kredensial Midtrans Toko Anda
                  </h2>
                  <p class="text-xs text-slate-400">Masukkan API Key Midtrans Anda sendiri. Pembayaran pelanggan akan langsung masuk ke akun Midtrans toko Anda.</p>
                </div>
                <span class="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">Terkoneksi</span>
              </div>

              <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <label class="block text-slate-400 mb-1">Midtrans Client Key (Frontend)</label>
                  <input type="text" id="store-midtrans-client" placeholder="SB-Mid-client-xxxxxxxx" value="\${userStore?.midtransClientKey || ''}" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200">
                </div>
                <div>
                  <label class="block text-slate-400 mb-1">Midtrans Server Key (Secret Worker)</label>
                  <input type="password" id="store-midtrans-server" placeholder="SB-Mid-server-xxxxxxxx" class="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200">
                </div>
              </div>

              <div class="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <span class="text-slate-400 block font-mono text-[11px]">URL Webhook Notification untuk Dashboard Midtrans Anda:</span>
                  <span class="text-orange-400 font-mono font-bold">\${window.location.origin}/api/midtrans-webhook/\${userStore?.id}</span>
                </div>
                <button onclick="saveMidtransSettings()" class="px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white font-bold rounded-lg shadow">Simpan Kunci</button>
              </div>
            </div>

            <!-- Bagian Upgrade Langganan SaaS PayPal -->
            <div class="bg-gradient-to-r from-slate-900 to-slate-800 border border-slate-800 rounded-2xl p-6 flex flex-col md:flex-row items-center justify-between gap-4">
              <div>
                <span class="text-[10px] font-bold uppercase tracking-wider text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded border border-amber-400/20">SaaS Plan: \${userStore?.plan || 'FREE'}</span>
                <h3 class="text-base font-bold text-white mt-1">Upgrade ke Pro Merchant untuk Fitur Tanpa Batas</h3>
                <p class="text-xs text-slate-400">Dapatkan skema dinamis tak terbatas dan prioritas edge caching dengan pembayaran PayPal.</p>
              </div>
              <button onclick="subscribePayPal('PRO')" class="px-5 py-2.5 bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-slate-950 font-bold text-xs rounded-xl shadow-lg">Langganan Pro ($15/bln)</button>
            </div>
          </div>
        \`;
      }
      lucide.createIcons();
    }

    function promptRegister() {
      const name = prompt("Nama Lengkap Anda:");
      const email = prompt("Email:");
      const password = prompt("Password:");
      const storeName = prompt("Nama Toko Anda:");
      if (!email || !password || !storeName) return;

      fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, storeName })
      }).then(r => r.json()).then(res => {
        if (res.success) {
          localStorage.setItem('token', res.token);
          localStorage.setItem('store', JSON.stringify(res.store));
          token = res.token;
          userStore = res.store;
          renderApp();
        } else {
          alert(res.error);
        }
      });
    }

    function promptLogin() {
      const email = prompt("Email:");
      const password = prompt("Password:");
      if (!email || !password) return;

      fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      }).then(r => r.json()).then(res => {
        if (res.success) {
          localStorage.setItem('token', res.token);
          localStorage.setItem('store', JSON.stringify(res.store));
          token = res.token;
          userStore = res.store;
          renderApp();
        } else {
          alert(res.error);
        }
      });
    }

    function saveMidtransSettings() {
      const clientKey = document.getElementById('store-midtrans-client').value.trim();
      const serverKey = document.getElementById('store-midtrans-server').value.trim();

      if (!clientKey || !serverKey) {
        alert("Client Key dan Server Key wajib diisi!");
        return;
      }

      fetch(\`/api/store/\${userStore.id}/settings/midtrans\`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ clientKey, serverKey, isProduction: false })
      }).then(r => r.json()).then(res => {
        if (res.success) {
          alert(res.message);
          userStore.midtransClientKey = clientKey;
          localStorage.setItem('store', JSON.stringify(userStore));
        } else {
          alert(res.error);
        }
      });
    }

    function subscribePayPal(plan) {
      fetch('/api/subscription/create-paypal-order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ plan })
      }).then(r => r.json()).then(res => {
        if (res.success && res.approvalUrl) {
          window.open(res.approvalUrl, '_blank');
        } else {
          alert(res.error || 'Gagal menghubungkan ke PayPal');
        }
      });
    }

    function logout() {
      localStorage.clear();
      token = null;
      userStore = null;
      renderApp();
    }
  </script>
</body>
</html>
  `);
});

export default app;