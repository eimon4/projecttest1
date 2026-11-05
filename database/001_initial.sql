CREATE TABLE users (
 id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('Admin','User')),
 active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users, expires_at TIMESTAMPTZ NOT NULL);
CREATE TABLE parties (
 id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('client','supplier')),
 name TEXT NOT NULL, contact TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
 email TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', archived BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE quotations (
 id BIGSERIAL PRIMARY KEY, number TEXT UNIQUE NOT NULL, client_id BIGINT NOT NULL REFERENCES parties,
 revision INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','final','accepted','lost')),
 data JSONB NOT NULL, created_by BIGINT NOT NULL REFERENCES users, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE quotation_versions (
 id BIGSERIAL PRIMARY KEY, quotation_id BIGINT NOT NULL REFERENCES quotations,
 revision INTEGER NOT NULL, snapshot JSONB NOT NULL, finalized_by BIGINT NOT NULL REFERENCES users,
 finalized_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(quotation_id,revision)
);
CREATE TABLE orders (
 id BIGSERIAL PRIMARY KEY, quotation_id BIGINT UNIQUE NOT NULL REFERENCES quotations,
 revision INTEGER NOT NULL, acceptance_reference TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE order_items (
 id BIGSERIAL PRIMARY KEY, order_id BIGINT NOT NULL REFERENCES orders, line_key TEXT NOT NULL,
 description TEXT NOT NULL, unit TEXT NOT NULL, ordered_milli BIGINT NOT NULL CHECK(ordered_milli>0),
 received_milli BIGINT NOT NULL DEFAULT 0 CHECK(received_milli>=0), delivered_milli BIGINT NOT NULL DEFAULT 0 CHECK(delivered_milli>=0),
 residual_milli BIGINT NOT NULL DEFAULT 0 CHECK(residual_milli>=0), cost_cents BIGINT NOT NULL CHECK(cost_cents>=0),
 price_cents BIGINT NOT NULL CHECK(price_cents>=0), supplier_id BIGINT REFERENCES parties,
 CHECK(delivered_milli+residual_milli<=received_milli), UNIQUE(order_id,line_key)
);
CREATE TABLE purchase_orders (
 id BIGSERIAL PRIMARY KEY, number TEXT UNIQUE NOT NULL, supplier_id BIGINT NOT NULL REFERENCES parties,
 order_id BIGINT NOT NULL REFERENCES orders, terms TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','cancelled')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE purchase_order_items (
 id BIGSERIAL PRIMARY KEY, po_id BIGINT NOT NULL REFERENCES purchase_orders, order_item_id BIGINT NOT NULL REFERENCES order_items,
 quantity_milli BIGINT NOT NULL CHECK(quantity_milli>0), received_milli BIGINT NOT NULL DEFAULT 0 CHECK(received_milli>=0 AND received_milli<=quantity_milli),
 cost_cents BIGINT NOT NULL CHECK(cost_cents>=0), UNIQUE(po_id,order_item_id)
);
CREATE TABLE receipts (
 id BIGSERIAL PRIMARY KEY, po_id BIGINT NOT NULL REFERENCES purchase_orders, reference TEXT NOT NULL,
 received_at DATE NOT NULL, notes TEXT NOT NULL DEFAULT '', lines JSONB NOT NULL, created_by BIGINT NOT NULL REFERENCES users
);
CREATE TABLE deliveries (
 id BIGSERIAL PRIMARY KEY, order_id BIGINT NOT NULL REFERENCES orders, reference TEXT UNIQUE NOT NULL,
 delivered_at DATE NOT NULL, accepted_by TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', lines JSONB NOT NULL, created_by BIGINT NOT NULL REFERENCES users
);
CREATE TABLE stock_lots (
 id BIGSERIAL PRIMARY KEY, description TEXT NOT NULL, unit TEXT NOT NULL, quantity_milli BIGINT NOT NULL CHECK(quantity_milli>=0),
 cost_cents BIGINT NOT NULL CHECK(cost_cents>=0), status TEXT NOT NULL CHECK(status IN ('available','for_return','damaged')),
 reason TEXT NOT NULL, location TEXT NOT NULL DEFAULT '', source_item_id BIGINT REFERENCES order_items,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE stock_reservations (
 id BIGSERIAL PRIMARY KEY, lot_id BIGINT NOT NULL REFERENCES stock_lots, order_item_id BIGINT NOT NULL REFERENCES order_items,
 quantity_milli BIGINT NOT NULL CHECK(quantity_milli>0), status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','issued','released')),
 created_by BIGINT NOT NULL REFERENCES users, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE stock_movements (
 id BIGSERIAL PRIMARY KEY, lot_id BIGINT NOT NULL REFERENCES stock_lots, quantity_milli BIGINT NOT NULL,
 kind TEXT NOT NULL, reference TEXT NOT NULL, created_by BIGINT NOT NULL REFERENCES users, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE stock_requests (
 id BIGSERIAL PRIMARY KEY, lot_id BIGINT NOT NULL REFERENCES stock_lots, delta_milli BIGINT NOT NULL CHECK(delta_milli<>0),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 created_by BIGINT NOT NULL REFERENCES users, reviewed_by BIGINT REFERENCES users, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE attachments (
 id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL, record_id BIGINT NOT NULL, original_name TEXT NOT NULL,
 stored_name TEXT UNIQUE NOT NULL, mime TEXT NOT NULL, created_by BIGINT NOT NULL REFERENCES users, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE audit_logs (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users, action TEXT NOT NULL, details JSONB NOT NULL,
 ip TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON order_items(order_id);
CREATE INDEX ON stock_reservations(lot_id,status);
CREATE INDEX ON stock_reservations(order_item_id,status);
CREATE INDEX ON purchase_order_items(order_item_id);
CREATE INDEX ON audit_logs(created_at DESC);
CREATE INDEX ON attachments(kind,record_id);

CREATE TABLE catalog (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, unit TEXT NOT NULL);
