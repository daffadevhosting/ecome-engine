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

interface CartItem {
  id: string;
  qty: number;
  price: number;
  name: string;
}

type AppEnv = {
  Bindings: Env;
  Variables: {
    user: JwtPayload;
  };
};

export class CartSession implements DurableObject {
  constructor(private state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const action = url.pathname.replace(/^\//, '') || 'cart';

    if (request.method === 'GET' && action === 'cart') {
      const items = ((await this.state.storage.get('items')) ?? []) as CartItem[];
      return Response.json({ success: true, items });
    }

    if (request.method === 'POST' && action === 'add') {
      const payload = (await request.json().catch(() => ({}))) as Partial<CartItem>;
      const items = ((await this.state.storage.get('items')) ?? []) as CartItem[];
      const idx = items.findIndex(item => item.id === payload.id);

      if (idx >= 0) {
        items[idx].qty += Number(payload.qty || 1);
      } else {
        items.push({
          id: String(payload.id ?? crypto.randomUUID()),
          name: String(payload.name || 'Produk'),
          price: Number(payload.price || 0),
          qty: Number(payload.qty || 1),
        });
      }

      await this.state.storage.put('items', items);
      return Response.json({ success: true, items });
    }

    if (request.method === 'POST' && action === 'clear') {
      await this.state.storage.delete('items');
      return Response.json({ success: true, items: [] });
    }

    return Response.json({ success: false, error: 'Endpoint CartSession tidak valid' }, { status: 404 });
  }
}

const app = new Hono<AppEnv>();

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

app.get('/api/store/:storeId/dashboard', authMiddleware, async (c) => {
  try {
    const user = c.get('user') as JwtPayload;
    const storeId = c.req.param('storeId');

    const store = await c.env.DB.prepare(
      'SELECT * FROM stores WHERE id = ? AND user_id = ? LIMIT 1'
    ).bind(storeId, user.userId).first<any>();

    if (!store) {
      return c.json({ success: false, error: 'Toko tidak ditemukan atau akses ditolak' }, 403);
    }

    const [schemaRow, productsResult, ordersResult] = await Promise.all([
      c.env.DB.prepare('SELECT schema_json FROM store_schemas WHERE store_id = ? AND is_active = 1 LIMIT 1').bind(storeId).first<{ schema_json: string }>(),
      c.env.DB.prepare('SELECT * FROM products WHERE store_id = ? ORDER BY created_at DESC').bind(storeId).all(),
      c.env.DB.prepare('SELECT * FROM orders WHERE store_id = ? ORDER BY created_at DESC LIMIT 20').bind(storeId).all()
    ]);

    const schema = schemaRow ? JSON.parse(schemaRow.schema_json || '[]') : [];
    const products = productsResult.results.map((row: any) => ({
      id: row.id,
      name: row.name,
      price: Number(row.price),
      stock: Number(row.stock),
      imageUrl: row.image_url,
      attributes: JSON.parse(row.attributes_json || '{}')
    }));

    const orders = ordersResult.results.map((row: any) => ({
      id: row.id,
      customerName: row.customer_name,
      customerEmail: row.customer_email,
      totalAmount: Number(row.total_amount),
      status: row.status,
      createdAt: row.created_at
    }));

    return c.json({
      success: true,
      store: {
        id: store.id,
        name: store.name,
        slug: store.slug,
        plan: store.plan,
        status: store.status,
        midtransClientKey: store.midtrans_client_key || '',
        midtransIsProd: Boolean(store.midtrans_is_prod)
      },
      schema,
      products,
      orders
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

app.get('/api/store/:storeId/orders', authMiddleware, async (c) => {
  try {
    const user = c.get('user') as JwtPayload;
    const storeId = c.req.param('storeId');
    const store = await c.env.DB.prepare('SELECT id FROM stores WHERE id = ? AND user_id = ?').bind(storeId, user.userId).first();

    if (!store) {
      return c.json({ success: false, error: 'Akses ditolak' }, 403);
    }

    const { results } = await c.env.DB.prepare(
      'SELECT * FROM orders WHERE store_id = ? ORDER BY created_at DESC LIMIT 20'
    ).bind(storeId).all();

    return c.json({
      success: true,
      orders: results.map((row: any) => ({
        id: row.id,
        customerName: row.customer_name,
        customerEmail: row.customer_email,
        totalAmount: Number(row.total_amount),
        status: row.status,
        createdAt: row.created_at
      }))
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

// POST: Reservasi stok saat buyer menambahkan produk ke keranjang
app.post('/api/store/:storeId/inventory/reserve', async (c) => {
  try {
    const storeId = c.req.param('storeId');
    const { productId, cartId, quantity } = await c.req.json();
    const requestedQuantity = Number(quantity || 1);
    if (!productId || !cartId || !Number.isInteger(requestedQuantity) || requestedQuantity < 1) {
      return c.json({ success: false, error: 'Data reservasi stok tidak valid' }, 400);
    }

    const reservationId = 'RSV-' + crypto.randomUUID().slice(0, 12);
    const update = await c.env.DB.prepare(
      'UPDATE products SET stock = stock - ? WHERE id = ? AND store_id = ? AND stock >= ?'
    ).bind(requestedQuantity, productId, storeId, requestedQuantity).run();
    if (!update.meta.changes) return c.json({ success: false, error: 'Stok produk tidak mencukupi' }, 409);

    await c.env.DB.prepare(
      'INSERT INTO inventory_reservations (id, store_id, product_id, cart_id, quantity, status) VALUES (?, ?, ?, ?, ?, "reserved")'
    ).bind(reservationId, storeId, productId, String(cartId), requestedQuantity).run();

    const remaining = await c.env.DB.prepare('SELECT stock FROM products WHERE id = ?').bind(productId).first<{ stock: number }>();
    return c.json({ success: true, reservationId, remainingStock: Number(remaining?.stock || 0) });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

// POST: Lepaskan reservasi stok saat item dikeluarkan dari keranjang
app.post('/api/store/:storeId/inventory/release', async (c) => {
  try {
    const storeId = c.req.param('storeId');
    const { reservationId, cartId } = await c.req.json();
    const reservation = await c.env.DB.prepare(
      'SELECT product_id, quantity FROM inventory_reservations WHERE id = ? AND store_id = ? AND cart_id = ? AND status = "reserved"'
    ).bind(reservationId, storeId, String(cartId)).first<{ product_id: string; quantity: number }>();
    if (!reservation) return c.json({ success: false, error: 'Reservasi tidak ditemukan atau sudah diproses' }, 404);

    await c.env.DB.batch([
      c.env.DB.prepare('UPDATE products SET stock = stock + ? WHERE id = ? AND store_id = ?').bind(reservation.quantity, reservation.product_id, storeId),
      c.env.DB.prepare('UPDATE inventory_reservations SET status = "released" WHERE id = ?').bind(reservationId)
    ]);
    return c.json({ success: true });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
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

// PUT: Ubah Produk
app.put('/api/store/:storeId/products/:productId', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const productId = c.req.param('productId');
  const { name, price, stock, imageUrl, attributes } = await c.req.json();

  const store = await c.env.DB.prepare('SELECT id FROM stores WHERE id = ? AND user_id = ?')
    .bind(storeId, user.userId)
    .first();
  if (!store) return c.json({ success: false, error: 'Akses ditolak' }, 403);

  if (!name || Number(price) <= 0 || Number(stock) < 0) {
    return c.json({ success: false, error: 'Nama, harga, dan stok produk harus valid' }, 400);
  }

  const result = await c.env.DB.prepare(
    'UPDATE products SET name = ?, price = ?, stock = ?, image_url = ?, attributes_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND store_id = ?'
  ).bind(name, Number(price), Number(stock), imageUrl || '', JSON.stringify(attributes || {}), productId, storeId).run();

  if (!result.meta.changes) return c.json({ success: false, error: 'Produk tidak ditemukan' }, 404);
  return c.json({ success: true, message: 'Produk berhasil diperbarui' });
});

// DELETE: Hapus Produk
app.delete('/api/store/:storeId/products/:productId', authMiddleware, async (c) => {
  const user = c.get('user');
  const storeId = c.req.param('storeId');
  const productId = c.req.param('productId');

  const store = await c.env.DB.prepare('SELECT id FROM stores WHERE id = ? AND user_id = ?')
    .bind(storeId, user.userId)
    .first();
  if (!store) return c.json({ success: false, error: 'Akses ditolak' }, 403);

  const result = await c.env.DB.prepare('DELETE FROM products WHERE id = ? AND store_id = ?')
    .bind(productId, storeId)
    .run();
  if (!result.meta.changes) return c.json({ success: false, error: 'Produk tidak ditemukan' }, 404);
  return c.json({ success: true, message: 'Produk berhasil dihapus' });
});

// POST: Checkout Midtrans Menggunakan Kredensial Toko Terkait
app.post('/api/store/:storeId/checkout', async (c) => {
  try {
    const storeId = c.req.param('storeId');
    const body = await c.req.json();
    const customer = body.customer || {};
    const items = Array.isArray(body.items) ? body.items : [];
    const cartId = String(body.cartId || '');

    if (!items.length) {
      return c.json({ success: false, error: 'Keranjang belanja tidak boleh kosong' }, 400);
    }

    if (!cartId) return c.json({ success: false, error: 'ID keranjang tidak valid' }, 400);

    const totalAmount = Number(body.totalAmount || items.reduce((sum: number, item: any) => {
      const price = Number(item.price || 0);
      const qty = Number(item.quantity || item.qty || 1);
      return sum + (price * qty);
    }, 0));

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

    const normalizedItems = items.map((item: any) => ({
      id: item.productId || item.id,
      productId: item.productId || item.id,
      reservationId: '',
      name: item.name || 'Produk',
      price: Number(item.price || 0),
      quantity: Number(item.quantity || item.qty || 1)
    }));

    const reservationIds: string[] = [];
    for (const item of normalizedItems) {
      if (!Number.isInteger(item.quantity) || item.quantity < 1) {
        return c.json({ success: false, error: 'Jumlah produk tidak valid' }, 400);
      }
      const reservationId = 'RSV-' + crypto.randomUUID().slice(0, 12);
      const update = await c.env.DB.prepare(
        'UPDATE products SET stock = stock - ? WHERE id = ? AND store_id = ? AND stock >= ?'
      ).bind(item.quantity, item.productId, storeId, item.quantity).run();
      if (!update.meta.changes) {
        for (const reservedId of reservationIds) {
          const reserved = await c.env.DB.prepare('SELECT product_id, quantity FROM inventory_reservations WHERE id = ?').bind(reservedId).first<{ product_id: string; quantity: number }>();
          if (reserved) await c.env.DB.batch([
            c.env.DB.prepare('UPDATE products SET stock = stock + ? WHERE id = ? AND store_id = ?').bind(reserved.quantity, reserved.product_id, storeId),
            c.env.DB.prepare('UPDATE inventory_reservations SET status = "released" WHERE id = ?').bind(reservedId)
          ]);
        }
        return c.json({ success: false, error: 'Stok produk tidak mencukupi' }, 409);
      }
      await c.env.DB.prepare(
        'INSERT INTO inventory_reservations (id, store_id, product_id, cart_id, quantity, status) VALUES (?, ?, ?, ?, ?, "reserved")'
      ).bind(reservationId, storeId, item.productId, cartId, item.quantity).run();
      reservationIds.push(reservationId);
      item.reservationId = reservationId;
    }

    const authHeader = 'Basic ' + btoa(store.midtrans_server_key + ':');
    const midtransRes = await fetch(`${baseUrl}/transactions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader
      },
      body: JSON.stringify({
        transaction_details: { order_id: orderId, gross_amount: totalAmount },
        customer_details: {
          first_name: customer.name || 'Pembeli',
          email: customer.email || 'guest@store.local',
          phone: customer.phone || '081234567890'
        },
        item_details: normalizedItems.map((item: any) => ({
          id: item.id,
          price: Math.max(0, item.price),
          quantity: Math.max(1, item.quantity),
          name: item.name
        }))
      })
    });

    const snapData = await midtransRes.json<any>();

    if (!midtransRes.ok) {
      for (const reservationId of reservationIds) {
        const reservation = await c.env.DB.prepare(
          'SELECT product_id, quantity FROM inventory_reservations WHERE id = ? AND store_id = ? AND status = "reserved"'
        ).bind(reservationId, storeId).first<{ product_id: string; quantity: number }>();
        if (reservation) {
          await c.env.DB.batch([
            c.env.DB.prepare('UPDATE products SET stock = stock + ? WHERE id = ? AND store_id = ?').bind(reservation.quantity, reservation.product_id, storeId),
            c.env.DB.prepare('UPDATE inventory_reservations SET status = "released" WHERE id = ?').bind(reservationId)
          ]);
        }
      }
      return c.json({ success: false, error: 'Gagal membuat transaksi Midtrans', details: snapData }, 502);
    }

    await c.env.DB.prepare(
      'INSERT INTO orders (id, store_id, customer_name, customer_email, customer_phone, total_amount, status, snap_token, items_json) VALUES (?, ?, ?, ?, ?, ?, "pending", ?, ?)'
    ).bind(
      orderId,
      storeId,
      customer.name || 'Pembeli',
      customer.email || 'guest@store.local',
      customer.phone || '081234567890',
      totalAmount,
      snapData.token,
      JSON.stringify(normalizedItems)
    ).run();

    return c.json({
      success: true,
      orderId,
      snapToken: snapData.token,
      redirectUrl: snapData.redirect_url,
      totalAmount
    });
  } catch (err: any) {
    return c.json({ success: false, error: err.message }, 500);
  }
});

// GET: Status order untuk sinkronisasi storefront buyer
app.get('/api/store/:storeId/orders/:orderId/status', async (c) => {
  const order = await c.env.DB.prepare(
    'SELECT id, status FROM orders WHERE id = ? AND store_id = ? LIMIT 1'
  ).bind(c.req.param('orderId'), c.req.param('storeId')).first<{ id: string; status: string }>();
  if (!order) return c.json({ success: false, error: 'Order tidak ditemukan' }, 404);
  return c.json({ success: true, orderId: order.id, status: order.status });
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

    // Reservasi sudah mengurangi stok saat masuk keranjang; webhook hanya finalisasi statusnya.
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
          if (item.reservationId) {
            batchOps.push(
              c.env.DB.prepare('UPDATE inventory_reservations SET status = "consumed" WHERE id = ? AND store_id = ? AND status = "reserved"').bind(item.reservationId, storeId)
            );
          } else if (item.productId) {
            batchOps.push(
              c.env.DB.prepare('UPDATE products SET stock = MAX(0, stock - ?) WHERE id = ?').bind(item.quantity || 1, item.productId)
            );
          }
        }
        await c.env.DB.batch(batchOps);
      }
    } else {
      if (['failed', 'expired'].includes(orderStatus)) {
        const order = await c.env.DB.prepare('SELECT items_json FROM orders WHERE id = ? AND store_id = ?')
          .bind(order_id, storeId).first<{ items_json: string }>();
        if (order) {
          const releaseOps = [];
          for (const item of JSON.parse(order.items_json)) {
            if (item.reservationId) {
              const reservation = await c.env.DB.prepare(
                'SELECT product_id, quantity FROM inventory_reservations WHERE id = ? AND store_id = ? AND status = "reserved"'
              ).bind(item.reservationId, storeId).first<{ product_id: string; quantity: number }>();
              if (reservation) {
                releaseOps.push(
                  c.env.DB.prepare('UPDATE products SET stock = stock + ? WHERE id = ? AND store_id = ?').bind(reservation.quantity, reservation.product_id, storeId),
                  c.env.DB.prepare('UPDATE inventory_reservations SET status = "released" WHERE id = ?').bind(item.reservationId)
                );
              }
            }
          }
          if (releaseOps.length) await c.env.DB.batch(releaseOps);
        }
      }
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

function escapeHtml(value: unknown): string {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

// Halaman publik toko untuk pembeli
app.get('/store/:slug', async (c) => {
    const slug = c.req.param('slug');
    const store = await c.env.DB.prepare(
      'SELECT id, name, slug FROM stores WHERE slug = ? AND status = "ACTIVE" LIMIT 1'
    ).bind(slug).first<{ id: string; name: string; slug: string }>();

    if (!store) return c.html('<h1>Toko tidak ditemukan</h1>', 404);

    const { results } = await c.env.DB.prepare(
      'SELECT id, name, price, stock, image_url FROM products WHERE store_id = ? AND stock > 0 ORDER BY created_at DESC'
    ).bind(store.id).all();

    const products = results.map((row: any) => ({
      id: String(row.id),
      name: String(row.name),
      price: Number(row.price),
      stock: Number(row.stock),
      imageUrl: row.image_url || ''
    }));

    const productCards = products.length
      ? products.map((product) => `<article class="product"><div class="product-image">${product.imageUrl ? `<img src="${escapeHtml(product.imageUrl)}" alt="${escapeHtml(product.name)}">` : '<span>Produk</span>'}</div><div class="product-body"><h2>${escapeHtml(product.name)}</h2><p class="price">Rp ${new Intl.NumberFormat('id-ID').format(product.price)}</p><p class="stock">${product.stock} tersedia</p><button class="add" data-product-id="${escapeHtml(product.id)}">Tambah ke keranjang</button></div></article>`).join('')
      : '<p class="empty">Belum ada produk tersedia.</p>';

    const productData = JSON.stringify(products).replace(/</g, '\\u003c');
    return c.html(`<!DOCTYPE html>
  <html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(store.name)}</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; } body { margin: 0; background: #101418; color: #f4f1ea; } header { border-bottom: 1px solid #2c3539; padding: 28px max(20px, calc((100% - 1120px) / 2)); } main { max-width: 1120px; margin: auto; padding: 36px 20px 64px; } .eyebrow { color: #f59e0b; font-size: 12px; text-transform: uppercase; letter-spacing: .14em; } h1 { margin: 8px 0 0; font-size: clamp(28px, 5vw, 48px); } .layout { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 28px; margin-top: 34px; } .products { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; } .product, .cart { border: 1px solid #2c3539; background: #171d21; border-radius: 12px; overflow: hidden; } .product-image { aspect-ratio: 4 / 3; background: #252d31; display: grid; place-items: center; color: #9ca6a8; } .product-image img { width: 100%; height: 100%; object-fit: cover; } .product-body, .cart { padding: 16px; } h2 { font-size: 16px; margin: 0 0 8px; } .price { color: #fbbf24; font-weight: 700; margin: 0; } .stock { color: #9ca6a8; font-size: 12px; } button { border: 0; border-radius: 8px; cursor: pointer; font: inherit; } .add, .checkout { background: #f59e0b; color: #17110a; font-weight: 700; padding: 11px 14px; width: 100%; } .cart { align-self: start; position: sticky; top: 20px; } .cart h2 { font-size: 20px; } .cart-row { border-bottom: 1px solid #2c3539; padding: 10px 0; display: flex; justify-content: space-between; gap: 10px; font-size: 13px; } .cart-row button { background: transparent; color: #f87171; font-size: 12px; } label { display: block; color: #9ca6a8; font-size: 12px; margin: 14px 0 5px; } input { box-sizing: border-box; width: 100%; padding: 11px; border: 1px solid #3b464a; border-radius: 8px; background: #101418; color: white; } .total { display: flex; justify-content: space-between; margin: 18px 0; font-weight: 700; } .empty { color: #9ca6a8; } .global-dialog { display: none; position: fixed; inset: 0; z-index: 20; place-items: center; padding: 20px; background: rgba(0,0,0,.72); } .global-dialog.open { display: grid; } .dialog-box { width: min(100%, 380px); padding: 24px; border: 1px solid #3b464a; border-radius: 12px; background: #171d21; box-shadow: 0 20px 60px rgba(0,0,0,.45); } .dialog-title { margin: 0; font-size: 18px; font-weight: 700; } .dialog-message { color: #b8c0c2; line-height: 1.5; } .dialog-primary { background: #f59e0b; color: #17110a; padding: 10px 16px; font-weight: 700; } @media (max-width: 760px) { .layout { grid-template-columns: 1fr; } .cart { position: static; } }
  </style></head><body><header><div class="eyebrow">Storefront</div><h1>${escapeHtml(store.name)}</h1></header><main><div class="layout"><section><div class="products">${productCards}</div></section><aside class="cart"><h2>Keranjang</h2><div id="cart-items"><p class="empty">Keranjang masih kosong.</p></div><div class="total"><span>Total</span><span id="cart-total">Rp 0</span></div><form id="checkout-form"><label for="customer-name">Nama</label><input id="customer-name" required><label for="customer-email">Email</label><input id="customer-email" type="email" required><label for="customer-phone">Telepon</label><input id="customer-phone" required><button class="checkout" type="submit">Bayar via Midtrans</button></form></aside></div></main>
  <script>window.STORE_PRODUCTS = ${productData}; window.STORE_ID = ${JSON.stringify(store.id)};</script>
  <script>
    const products = window.STORE_PRODUCTS; const cartId = localStorage.getItem('cartId') || crypto.randomUUID(); localStorage.setItem('cartId', cartId); const cartStorageKey = 'cart:' + window.STORE_ID; const cart = JSON.parse(localStorage.getItem(cartStorageKey) || '[]');
    function showAlert(message, title = 'Informasi') { document.getElementById('global-alert-title').textContent = title; document.getElementById('global-alert-message').textContent = message; document.getElementById('global-alert').classList.add('open'); }
    function closeAlert() { document.getElementById('global-alert').classList.remove('open'); }
    const money = value => 'Rp ' + new Intl.NumberFormat('id-ID').format(value);
    function renderCart() {
      const items = document.getElementById('cart-items');
      document.getElementById('cart-total').textContent = money(cart.reduce((sum, item) => sum + item.price * item.quantity, 0));
      localStorage.setItem(cartStorageKey, JSON.stringify(cart)); items.innerHTML = cart.length ? cart.map(item => '<div class="cart-row"><span>' + item.name + ' x ' + item.quantity + '</span><button type="button" data-remove-id="' + item.id + '">Hapus</button></div>').join('') : '<p class="empty">Keranjang masih kosong.</p>';
      items.querySelectorAll('[data-remove-id]').forEach(button => button.addEventListener('click', async () => { const item = cart.find(entry => entry.id === button.dataset.removeId); if (!item) return; item.quantity -= 1; if (item.quantity <= 0) cart.splice(cart.indexOf(item), 1); renderCart(); }));
    }
    document.querySelectorAll('[data-product-id]').forEach(button => button.addEventListener('click', () => { const product = products.find(item => item.id === button.dataset.productId); if (!product) return; const item = cart.find(entry => entry.id === product.id); if (item) item.quantity += 1; else cart.push({ ...product, quantity: 1 }); renderCart(); }));
    renderCart();
    document.getElementById('checkout-form').addEventListener('submit', async event => { event.preventDefault(); if (!cart.length) return showAlert('Keranjang masih kosong.', 'Keranjang'); const body = { cartId, customer: { name: document.getElementById('customer-name').value, email: document.getElementById('customer-email').value, phone: document.getElementById('customer-phone').value }, items: cart, totalAmount: cart.reduce((sum, item) => sum + item.price * item.quantity, 0) }; const response = await fetch('/api/store/' + window.STORE_ID + '/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); const result = await response.json(); if (!result.success) return showAlert(result.error || 'Checkout gagal.', 'Checkout'); if (result.redirectUrl) window.open(result.redirectUrl, '_blank'); let attempts = 0; const poll = setInterval(async () => { attempts += 1; const statusResponse = await fetch('/api/store/' + window.STORE_ID + '/orders/' + result.orderId + '/status'); const statusResult = await statusResponse.json(); if (statusResult.status === 'paid') { clearInterval(poll); localStorage.removeItem(cartStorageKey); cart.splice(0, cart.length); renderCart(); showAlert('Pembayaran berhasil.', 'Pembayaran'); } else if (['failed', 'expired'].includes(statusResult.status) || attempts >= 60) clearInterval(poll); }, 5000); });
  </script><div id="global-alert" class="global-dialog"><div class="dialog-box"><p id="global-alert-title" class="dialog-title">Informasi</p><p id="global-alert-message" class="dialog-message"></p><button type="button" class="dialog-primary" onclick="closeAlert()">Mengerti</button></div></div></body></html>`);
});

/**
 * ============================================================================
 * 6. DASHBOARD & STOREFRONT SPA (DIHOSTING LANGSUNG OLEH WORKER)
 * ============================================================================
 */
app.get('*', (c) => {
  const html = `
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

  <main class="flex-grow max-w-7xl w-full mx-auto px-4 py-8" id="app-root"></main>

  <script>
    let token = localStorage.getItem('token');
    let userStore = JSON.parse(localStorage.getItem('store') || 'null');
    let authMode = 'login';
    let dashboardData = { products: [], orders: [], schema: [] };
    let cart = [];
    let confirmResolver;

    function showAlert(message, title = 'Informasi') {
      document.getElementById('global-alert-title').textContent = title;
      document.getElementById('global-alert-message').textContent = message;
      document.getElementById('global-alert').classList.add('flex');
    }

    function closeAlert() {
      document.getElementById('global-alert').classList.remove('flex');
    }

    function showConfirm(message, title = 'Konfirmasi') {
      document.getElementById('global-confirm-title').textContent = title;
      document.getElementById('global-confirm-message').textContent = message;
      document.getElementById('global-confirm').classList.add('flex');
      return new Promise(resolve => { confirmResolver = resolve; });
    }

    function resolveConfirm(value) {
      document.getElementById('global-confirm').classList.remove('flex');
      if (confirmResolver) confirmResolver(value);
      confirmResolver = null;
    }

    function bindAuthModal() {
      const modal = document.getElementById('auth-modal');
      if (!modal) return;
      modal.addEventListener('click', (event) => {
        if (event.target === modal) closeAuthModal();
      });
    }

    function openAuthModal(mode) {
      authMode = mode;
      const modal = document.getElementById('auth-modal');
      const title = document.getElementById('auth-title');
      const storeField = document.getElementById('register-store-field');
      const nameField = document.getElementById('register-name-field');
      const submitButton = document.getElementById('auth-submit');
      if (!modal || !title || !storeField || !nameField || !submitButton) return;

      title.textContent = mode === 'login' ? 'Masuk Merchant' : 'Buka Toko Baru';
      storeField.style.display = mode === 'register' ? 'block' : 'none';
      nameField.style.display = mode === 'register' ? 'block' : 'none';
      submitButton.textContent = mode === 'login' ? 'Masuk' : 'Buat Toko';
      modal.classList.remove('hidden');
      modal.classList.add('flex');

      const emailInput = document.getElementById('auth-email');
      const passwordInput = document.getElementById('auth-password');
      const nameInput = document.getElementById('auth-name');
      const storeInput = document.getElementById('auth-store-name');
      if (emailInput) emailInput.focus();
      if (nameInput) nameInput.value = '';
      if (passwordInput) passwordInput.value = '';
      if (storeInput) storeInput.value = '';
    }

    function closeAuthModal() {
      const modal = document.getElementById('auth-modal');
      if (!modal) return;
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }

    function submitAuthForm(event) {
      event.preventDefault();
      const formData = new FormData(event.currentTarget);
      const payload = {
        email: formData.get('email')?.toString().trim(),
        password: formData.get('password')?.toString(),
        name: formData.get('name')?.toString().trim(),
        storeName: formData.get('storeName')?.toString().trim(),
      };

      if (!payload.email || !payload.password) {
        showAlert('Email dan password wajib diisi.');
        return;
      }

      if (authMode === 'register') {
        if (!payload.name || !payload.storeName) {
          showAlert('Nama lengkap dan nama toko wajib diisi.');
          return;
        }

        fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        }).then(r => r.json()).then(res => {
          if (res.success) {
            localStorage.setItem('token', res.token);
            localStorage.setItem('store', JSON.stringify(res.store));
            token = res.token;
            userStore = res.store;
            closeAuthModal();
            renderApp();
          } else {
            showAlert(res.error, 'Registrasi gagal');
          }
        });
        return;
      }

      fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: payload.email, password: payload.password })
      }).then(r => r.json()).then(res => {
        if (res.success) {
          localStorage.setItem('token', res.token);
          localStorage.setItem('store', JSON.stringify(res.store));
          token = res.token;
          userStore = res.store;
          closeAuthModal();
          renderApp();
        } else {
          showAlert(res.error, 'Login gagal');
        }
      });
    }

    async function loadDashboardData() {
      if (!userStore || !userStore.id) return;
      try {
        const res = await fetch('/api/store/' + userStore.id + '/dashboard', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (!data.success) {
          showAlert(data.error || 'Gagal mengambil data dashboard.', 'Dashboard gagal dimuat');
          return;
        }
        dashboardData = data;
        renderMerchantDashboard();
      } catch (error) {
        showAlert('Gagal mengambil data toko.', 'Koneksi gagal');
      }
    }

    function renderMerchantDashboard() {
      const root = document.getElementById('app-root');
      if (!root) return;

      const totalRevenue = dashboardData.orders.reduce((sum, order) => sum + Number(order.totalAmount || 0), 0);
      const totalProducts = dashboardData.products.length;
      const productStock = dashboardData.products.reduce((sum, product) => sum + Number(product.stock || 0), 0);
      const cartTotal = cart.reduce((sum, item) => sum + (Number(item.price || 0) * Number(item.quantity || 1)), 0);

      const productCards = dashboardData.products.length
        ? dashboardData.products.map((product) => {
            const imageMarkup = product.imageUrl
              ? '<img src="' + product.imageUrl + '" alt="' + product.name + '" class="h-full w-full object-cover" />'
              : '<div class="flex h-full w-full items-center justify-center text-xs text-slate-400">IMG</div>';
            return '<div class="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-950 p-3 md:flex-row md:items-center md:justify-between">'
              + '<div class="flex items-center gap-3">'
              + '<div class="h-14 w-14 overflow-hidden rounded-lg bg-slate-800">' + imageMarkup + '</div>'
              + '<div>'
              + '<p class="font-semibold text-white">' + product.name + '</p>'
              + '<p class="text-xs text-slate-400">Stok: ' + product.stock + '</p>'
              + '<p class="text-xs text-orange-400">Rp ' + new Intl.NumberFormat('id-ID').format(Number(product.price || 0)) + '</p>'
              + '</div>'
              + '</div>'
              + '<div class="flex items-center gap-2">'
              + '<button onclick="editProductById(this.dataset.id)" data-id="' + product.id + '" class="rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-300">Edit</button>'
              + '<button onclick="deleteProductById(this.dataset.id)" data-id="' + product.id + '" class="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-300">Hapus</button>'
              + '</div>'
              + '</div>';
          }).join('')
        : '<div class="rounded-xl border border-dashed border-slate-700 p-4 text-sm text-slate-400">Belum ada produk. Tambahkan yang pertama.</div>';

      const cartList = cart.length
        ? cart.map((item) => {
            return '<div class="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-2 text-sm">'
              + '<div>'
              + '<p class="font-medium text-white">' + item.name + '</p>'
              + '<p class="text-slate-400">' + item.quantity + ' x Rp ' + new Intl.NumberFormat('id-ID').format(Number(item.price || 0)) + '</p>'
              + '</div>'
              + '<button onclick="removeFromCartById(this.dataset.id)" data-id="' + item.id + '" class="text-xs text-red-400">Hapus</button>'
              + '</div>';
          }).join('')
        : '<div class="rounded-xl border border-dashed border-slate-700 p-4 text-sm text-slate-400">Belum ada item di keranjang.</div>';

      const orderList = dashboardData.orders.length
        ? dashboardData.orders.map((order) => {
            return '<div class="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-3 text-sm">'
              + '<div>'
              + '<p class="font-medium text-white">' + order.customerName + '</p>'
              + '<p class="text-slate-400">' + order.id + '</p>'
              + '</div>'
              + '<div class="text-right">'
              + '<p class="font-semibold text-orange-400">Rp ' + new Intl.NumberFormat('id-ID').format(Number(order.totalAmount || 0)) + '</p>'
              + '<p class="text-xs text-slate-400">' + order.status + '</p>'
              + '</div>'
              + '</div>';
          }).join('')
        : '<div class="text-sm text-slate-400">Belum ada pesanan masuk.</div>';

      root.innerHTML = '<div class="space-y-6">'
        + '<div class="grid grid-cols-1 md:grid-cols-3 gap-4">'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4"><p class="text-xs uppercase text-slate-400">Produk</p><p class="mt-2 text-2xl font-bold text-white">' + totalProducts + '</p></div>'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4"><p class="text-xs uppercase text-slate-400">Stok Total</p><p class="mt-2 text-2xl font-bold text-white">' + productStock + '</p></div>'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4"><p class="text-xs uppercase text-slate-400">Omset Pesanan</p><p class="mt-2 text-2xl font-bold text-white">Rp ' + new Intl.NumberFormat('id-ID').format(totalRevenue) + '</p></div>'
        + '</div>'
        + '<div class="grid grid-cols-1 xl:grid-cols-[1.5fr_0.9fr] gap-6">'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4">'
        + '<div class="mb-4 flex items-center justify-between"><h3 class="text-lg font-bold text-white">Produk Toko</h3><button onclick="document.getElementById(&#39;product-form&#39;).scrollIntoView({behavior:&#39;smooth&#39;})" class="rounded-xl bg-orange-500 px-3 py-2 text-xs font-bold text-white">Tambah Produk</button></div>'
        + '<div id="product-form" class="mb-6 rounded-xl border border-slate-800 bg-slate-950 p-4"><div class="mb-3 flex items-center justify-between"><h4 id="product-form-title" class="text-sm font-bold text-white">Tambah Produk</h4><button id="cancel-product-edit" type="button" onclick="cancelProductEdit()" class="hidden text-xs text-slate-400">Batal edit</button></div><form id="add-product-form" onsubmit="handleAddProduct(event)"><input id="product-id" type="hidden"><div class="grid grid-cols-1 md:grid-cols-2 gap-3"><div><label class="mb-1 block text-xs text-slate-400">Nama Produk</label><input id="product-name" name="name" type="text" class="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white" placeholder="Contoh: Sepatu Trail" required></div><div><label class="mb-1 block text-xs text-slate-400">Harga (Rp)</label><input id="product-price" name="price" type="number" min="0" class="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white" placeholder="250000" required></div><div><label class="mb-1 block text-xs text-slate-400">Stok</label><input id="product-stock" name="stock" type="number" min="0" class="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white" placeholder="20" required></div><div><label class="mb-1 block text-xs text-slate-400">Gambar URL</label><input id="product-image" name="imageUrl" type="text" class="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white" placeholder="https://..."></div></div><div class="mt-3 flex justify-end"><button id="product-submit" type="submit" class="rounded-xl bg-orange-500 px-4 py-2 text-sm font-bold text-white">Simpan Produk</button></div></form></div>'
        + '<div class="space-y-3">' + productCards + '</div>'
        + '</div>'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4">'
        + '<div class="mb-4"><h3 class="text-lg font-bold text-white">Konfigurasi Midtrans</h3><p class="mt-1 text-xs text-slate-400">Kredensial ini digunakan untuk checkout toko dan disimpan di D1.</p></div>'
        + '<div class="space-y-3"><div><label class="mb-1 block text-xs text-slate-400">Client Key</label><input id="store-midtrans-client" type="text" value="' + (userStore?.midtransClientKey || '') + '" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white" placeholder="Mid-client-..."></div><div><label class="mb-1 block text-xs text-slate-400">Server Key</label><input id="store-midtrans-server" type="password" class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white" placeholder="Mid-server-..."></div><label class="flex items-center gap-2 text-xs text-slate-300"><input id="store-midtrans-production" type="checkbox" class="accent-orange-500" ' + (userStore?.midtransIsProd ? 'checked' : '') + '> Mode production</label><button onclick="saveMidtransSettings()" class="w-full rounded-xl bg-orange-500 px-4 py-3 text-sm font-bold text-white">Simpan Konfigurasi</button></div>'
        + '<div class="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-3"><p class="text-xs text-slate-400">URL notification Midtrans</p><p class="mt-2 break-all font-mono text-xs text-orange-400">' + window.location.origin + '/api/midtrans-webhook/' + userStore.id + '</p></div>'
        + '</div>'
        + '</div>'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900 p-4"><div class="mb-3 flex items-center justify-between"><h3 class="text-lg font-bold text-white">Pesanan Terbaru</h3></div><div class="space-y-2">' + orderList + '</div></div>'
        + '</div>';

      lucide.createIcons();
    }

    function addToCartById(productId) {
      const product = dashboardData.products.find((item) => String(item.id) === String(productId));
      if (product) addToCart(product);
    }

    function addToCart(product) {
      const productId = String(product.id);
      const existing = cart.find((item) => item.id === productId);
      if (existing) {
        existing.quantity = Number(existing.quantity || 0) + 1;
      } else {
        cart.push({ id: productId, name: product.name, price: Number(product.price), quantity: 1 });
      }
      renderMerchantDashboard();
    }

    function removeFromCart(productId) {
      cart = cart.filter((item) => item.id !== productId);
      renderMerchantDashboard();
    }

    function removeFromCartById(productId) {
      removeFromCart(String(productId));
    }

    function editProductById(productId) {
      const product = dashboardData.products.find((item) => String(item.id) === String(productId));
      if (!product) return;
      document.getElementById('product-id').value = product.id;
      document.getElementById('product-name').value = product.name || '';
      document.getElementById('product-price').value = Number(product.price || 0);
      document.getElementById('product-stock').value = Number(product.stock || 0);
      document.getElementById('product-image').value = product.imageUrl || '';
      document.getElementById('product-form-title').textContent = 'Edit Produk';
      document.getElementById('product-submit').textContent = 'Perbarui Produk';
      document.getElementById('cancel-product-edit').classList.remove('hidden');
      document.getElementById('product-form').scrollIntoView({ behavior: 'smooth' });
    }

    function cancelProductEdit() {
      const form = document.getElementById('add-product-form');
      form.reset();
      document.getElementById('product-id').value = '';
      document.getElementById('product-form-title').textContent = 'Tambah Produk';
      document.getElementById('product-submit').textContent = 'Simpan Produk';
      document.getElementById('cancel-product-edit').classList.add('hidden');
    }

    async function deleteProductById(productId) {
      if (!(await showConfirm('Hapus produk ini?', 'Hapus produk'))) return;
      try {
        const res = await fetch('/api/store/' + userStore.id + '/products/' + productId, {
          method: 'DELETE',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (!data.success) {
          showAlert(data.error || 'Gagal menghapus produk.', 'Hapus produk gagal');
          return;
        }
        await loadDashboardData();
      } catch (error) {
        showAlert('Gagal menghapus produk.', 'Koneksi gagal');
      }
    }

    async function handleAddProduct(event) {
      event.preventDefault();
      const form = event.currentTarget;
      const formData = new FormData(event.currentTarget);
      const productId = document.getElementById('product-id').value;
      const payload = {
        name: String(formData.get('name') || '').trim(),
        price: Number(formData.get('price') || 0),
        stock: Number(formData.get('stock') || 0),
        imageUrl: String(formData.get('imageUrl') || '').trim(),
        attributes: { ukuran: 'Standar' }
      };

      if (!payload.name || !payload.price || payload.price <= 0) {
        showAlert('Nama produk dan harga harus valid.', 'Data produk tidak valid');
        return;
      }

      try {
        const res = await fetch('/api/store/' + userStore.id + '/products' + (productId ? '/' + productId : ''), {
          method: productId ? 'PUT' : 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
          },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!data.success) {
          showAlert(data.error || 'Gagal menyimpan produk.', 'Produk gagal disimpan');
          return;
        }
        cancelProductEdit();
        await loadDashboardData();
      } catch (err) {
        showAlert('Gagal menyimpan produk.', 'Koneksi gagal');
      }
    }

    async function handleCheckout() {
      if (!cart.length) {
        showAlert('Keranjang masih kosong.', 'Checkout');
        return;
      }

      const name = document.getElementById('checkout-name')?.value?.trim() || 'Pembeli';
      const email = document.getElementById('checkout-email')?.value?.trim() || 'guest@store.local';
      const phone = document.getElementById('checkout-phone')?.value?.trim() || '081234567890';
      const totalAmount = cart.reduce((sum, item) => sum + (Number(item.price || 0) * Number(item.quantity || 1)), 0);

      try {
        const res = await fetch('/api/store/' + userStore.id + '/checkout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            customer: { name, email, phone },
            items: cart,
            totalAmount
          })
        });
        const data = await res.json();
        if (!data.success) {
          showAlert(data.error || 'Checkout gagal.', 'Checkout gagal');
          return;
        }

        showAlert('Transaksi berhasil dibuat. Order ID: ' + data.orderId, 'Checkout berhasil');
        cart = [];
        await loadDashboardData();
        if (data.redirectUrl) {
          window.open(data.redirectUrl, '_blank');
        }
      } catch (error) {
        showAlert('Gagal memproses checkout Midtrans.', 'Checkout gagal');
      }
    }

    function renderApp() {
      const nav = document.getElementById('nav-actions');
      const root = document.getElementById('app-root');

      if (!token) {
        nav.innerHTML = '<button onclick="openAuthModal(&#39;login&#39;)" class="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl">Masuk Merchant</button><button onclick="openAuthModal(&#39;register&#39;)" class="px-4 py-2 text-xs font-semibold bg-orange-500 hover:bg-orange-600 text-white rounded-xl shadow-lg shadow-orange-500/20">Buka Toko Baru</button>';
        root.innerHTML = '<div class="text-center max-w-3xl mx-auto py-12 space-y-6"><span class="px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">Dukungan Multi-Tenant Midtrans + Skema Dinamis</span><h1 class="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">Platform E-Commerce Modern dengan <span class="text-orange-400">Midtrans Mandiri</span></h1><p class="text-slate-400 text-sm leading-relaxed">Setiap pemilik toko dapat memasukkan Server Key & Client Key Midtrans milik masing-masing. Dana penjualan langsung masuk ke rekening toko Anda tanpa potongan platform.</p><div class="flex justify-center gap-4 pt-4"><button onclick="openAuthModal(&#39;register&#39;)" class="px-6 py-3 bg-orange-500 hover:bg-orange-600 text-white font-bold rounded-xl text-sm shadow-xl shadow-orange-500/25">Mulai Buka Toko Sekarang &rarr;</button></div></div>';
        return;
      }

      nav.innerHTML = '<span class="text-xs text-slate-400">Toko: <strong class="text-white">' + (userStore?.name || 'Toko Saya') + '</strong> (' + (userStore?.plan || 'FREE') + ')</span><button onclick="logout()" class="px-3 py-1.5 text-xs bg-red-500/20 text-red-400 border border-red-500/30 rounded-xl hover:bg-red-500/30">Keluar</button>';
      root.innerHTML = '<div class="space-y-4 rounded-2xl border border-slate-800 bg-slate-900 p-6"><div class="flex items-center justify-between"><div><p class="text-xs uppercase tracking-[0.2em] text-orange-400">Merchant Dashboard</p><h2 class="mt-2 text-2xl font-bold text-white">' + (userStore?.name || 'Toko Saya') + '</h2></div><button onclick="loadDashboardData()" class="rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-white">Refresh</button></div><div class="rounded-xl border border-slate-800 bg-slate-950 p-3 text-sm text-slate-300">Link toko pembeli: <a class="font-mono text-orange-400 underline" href="/store/' + (userStore?.slug || '') + '" target="_blank">' + window.location.origin + '/store/' + (userStore?.slug || '') + '</a></div></div>';

      loadDashboardData();
      lucide.createIcons();
    }

    function saveMidtransSettings() {
      const clientKey = document.getElementById('store-midtrans-client')?.value?.trim();
      const serverKey = document.getElementById('store-midtrans-server')?.value?.trim();
      const isProduction = document.getElementById('store-midtrans-production')?.checked || false;
      if (!clientKey || !serverKey) {
        showAlert('Client Key dan Server Key wajib diisi!', 'Konfigurasi Midtrans');
        return;
      }

      fetch('/api/store/' + userStore.id + '/settings/midtrans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ clientKey, serverKey, isProduction })
      }).then(r => r.json()).then(res => {
        if (res.success) {
          showAlert(res.message, 'Midtrans tersimpan');
          userStore.midtransClientKey = clientKey;
          userStore.midtransIsProd = isProduction;
          localStorage.setItem('store', JSON.stringify(userStore));
        } else {
          showAlert(res.error, 'Konfigurasi gagal');
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
          showAlert(res.error || 'Gagal menghubungkan ke PayPal', 'PayPal gagal');
        }
      });
    }

    function logout() {
      localStorage.clear();
      token = null;
      userStore = null;
      dashboardData = { products: [], orders: [], schema: [] };
      cart = [];
      renderApp();
    }

    document.addEventListener('DOMContentLoaded', () => {
      renderApp();
      bindAuthModal();
    });
  </script>

  <div id="auth-modal" class="hidden fixed inset-0 z-50 items-center justify-center bg-slate-950/80 backdrop-blur-sm">
    <div class="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
      <div class="mb-4 flex items-center justify-between">
        <h3 id="auth-title" class="text-xl font-bold text-white">Masuk Merchant</h3>
        <button type="button" onclick="closeAuthModal()" class="text-slate-400 hover:text-white">✕</button>
      </div>

      <form id="auth-form" onsubmit="submitAuthForm(event)">
        <div id="register-name-field" class="mb-3 hidden">
          <label class="mb-1 block text-sm text-slate-300">Nama Lengkap</label>
          <input id="auth-name" name="name" type="text" class="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none ring-0" placeholder="Nama lengkap Anda">
        </div>

        <div class="mb-3">
          <label class="mb-1 block text-sm text-slate-300">Email</label>
          <input id="auth-email" name="email" type="email" class="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none ring-0" placeholder="merchant@email.com">
        </div>

        <div class="mb-3">
          <label class="mb-1 block text-sm text-slate-300">Password</label>
          <input id="auth-password" name="password" type="password" class="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none ring-0" placeholder="Masukkan password">
        </div>

        <div id="register-store-field" class="mb-4 hidden">
          <label class="mb-1 block text-sm text-slate-300">Nama Toko</label>
          <input id="auth-store-name" name="storeName" type="text" class="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none ring-0" placeholder="Contoh: Toko Bunga Art">
        </div>

        <button id="auth-submit" type="submit" class="w-full rounded-xl bg-orange-500 px-4 py-3 font-bold text-white hover:bg-orange-600">Masuk</button>
      </form>
    </div>
  </div>

  <div id="global-alert" class="hidden fixed inset-0 z-[60] items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
    <div class="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
      <h3 id="global-alert-title" class="text-lg font-bold text-white">Informasi</h3>
      <p id="global-alert-message" class="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-300"></p>
      <div class="mt-5 flex justify-end"><button type="button" onclick="closeAlert()" class="rounded-xl bg-orange-500 px-4 py-2 text-sm font-bold text-white">Mengerti</button></div>
    </div>
  </div>

  <div id="global-confirm" class="hidden fixed inset-0 z-[60] items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
    <div class="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
      <h3 id="global-confirm-title" class="text-lg font-bold text-white">Konfirmasi</h3>
      <p id="global-confirm-message" class="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-300"></p>
      <div class="mt-5 flex justify-end gap-3"><button type="button" onclick="resolveConfirm(false)" class="rounded-xl border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-300">Batal</button><button type="button" onclick="resolveConfirm(true)" class="rounded-xl bg-red-500 px-4 py-2 text-sm font-bold text-white">Lanjutkan</button></div>
    </div>
  </div>
</body>
</html>`;

  return c.html(html);
});

export default app;