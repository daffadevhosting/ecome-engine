-- ============================================================================
-- CLOUDFLARE D1 SQL SCHEMA: MULTI-TENANT E-COMMERCE SAAS & MIDTRANS ENGINE
-- ============================================================================

-- 1. TABEL PENGGUNA (USERS / MERCHANT)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
-- Format: USR-xxxxxxxx
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. TABEL TOKO / TENANT (STORES)
-- Menyimpan profil toko, paket langganan, serta kredensial Midtrans mandiri
CREATE TABLE IF NOT EXISTS stores (
    id TEXT PRIMARY KEY,                       -- Format: STORE-xxxxxxxx
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,                 -- URL path toko: /store/nama-toko
    plan TEXT DEFAULT 'FREE',                  -- FREE, PRO, ENTERPRISE
    status TEXT DEFAULT 'ACTIVE',              -- ACTIVE, SUSPENDED, EXPIRED
    midtrans_server_key TEXT,                  -- Server Key rahasia toko
    midtrans_client_key TEXT,                  -- Client Key publik toko
    midtrans_is_prod INTEGER DEFAULT 0,        -- 0 = Sandbox, 1 = Production
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. TABEL SKEMA DINAMIS PER TOKO (DYNAMIC SCHEMAS)
-- Menyimpan definisi atribut produk JSON yang dikustomisasi oleh toko
CREATE TABLE IF NOT EXISTS store_schemas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id TEXT NOT NULL,
    schema_json TEXT NOT NULL,                 -- Array of dynamic field definitions
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE
);

-- 4. TABEL KATALOG PRODUK (PRODUCTS)
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,                       -- Format: PROD-xxxxxxxx
    store_id TEXT NOT NULL,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,                    -- Harga dalam satuan dasar (IDR / Rupiah)
    stock INTEGER NOT NULL DEFAULT 0,
    image_url TEXT,                            -- Path file di R2 / link eksternal
    attributes_json TEXT NOT NULL,             -- Nilai atribut dinamis (e.g. {"ukuran":"XL", "warna":"#000"})
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE
);

-- 5. TABEL TRANSAKSI & PESANAN (ORDERS)
-- Menyimpan data checkout Midtrans Snap per tenant
CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,                       -- Format: ORD-xxxx-xxxxxxxx
    store_id TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    customer_phone TEXT,
    total_amount INTEGER NOT NULL,             -- Gross amount pesanan
    status TEXT DEFAULT 'pending',             -- pending, paid, challenge, failed, expired
    snap_token TEXT,                           -- Midtrans Snap token
    items_json TEXT NOT NULL,                  -- Snapshot data produk saat transaksi
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE
);

-- 6. RESERVASI STOK KERANJANG PEMBELI
CREATE TABLE IF NOT EXISTS inventory_reservations (
    id TEXT PRIMARY KEY,
    store_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    cart_id TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    status TEXT DEFAULT 'reserved', -- reserved, consumed, released
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

-- 6. TABEL RIWAYAT LANGGANAN SAAS PAYPAL (SUBSCRIPTIONS)
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,                       -- Format: SUB-xxxxxxxx
    user_id TEXT NOT NULL,
    plan TEXT NOT NULL,                        -- PRO, ENTERPRISE
    amount REAL NOT NULL,                      -- Harga USD (misal: 15.00)
    currency TEXT DEFAULT 'USD',
    paypal_order_id TEXT NOT NULL,             -- Order ID dari PayPal Worker
    status TEXT DEFAULT 'PENDING',             -- PENDING, PAID, CANCELLED
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEKS OPTIMASI QUERY UNTUK CLOUDFLARE D1
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_stores_user_id ON stores(user_id);
CREATE INDEX IF NOT EXISTS idx_stores_slug ON stores(slug);
CREATE INDEX IF NOT EXISTS idx_schemas_store_id ON store_schemas(store_id);
CREATE INDEX IF NOT EXISTS idx_products_store_id ON products(store_id);
CREATE INDEX IF NOT EXISTS idx_orders_store_id ON orders(store_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_reservations_cart ON inventory_reservations(cart_id, status);
CREATE INDEX IF NOT EXISTS idx_reservations_product ON inventory_reservations(product_id, status);