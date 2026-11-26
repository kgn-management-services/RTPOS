-- Encrypted BDI client credentials
CREATE TABLE IF NOT EXISTS bdi_clients (
    id              SERIAL PRIMARY KEY,
    client_code     VARCHAR(50) UNIQUE NOT NULL,       -- e.g. 'AMPCS', 'P4ALL', 'PRIME.T'
    display_name    VARCHAR(100) NOT NULL,
    login_url       TEXT NOT NULL DEFAULT 'https://myrtpos.com/newbdi/index.fwx',
    username_enc    TEXT NOT NULL,                     -- Fernet-encrypted BDI username
    password_enc    TEXT NOT NULL,                     -- Fernet-encrypted BDI password
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Individual employee accounts (revocable anytime without touching BDI passwords)
CREATE TABLE IF NOT EXISTS bdi_employees (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(100) UNIQUE NOT NULL,      -- Employee's own login ID
    full_name       VARCHAR(150) NOT NULL,
    password_hash   TEXT NOT NULL,                     -- PBKDF2-HMAC-SHA256 hash
    allowed_clients TEXT[] NOT NULL DEFAULT '{}',      -- e.g. ARRAY['AMPCS','P4ALL']
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- Full audit trail of every portal launch
CREATE TABLE IF NOT EXISTS bdi_access_logs (
    id              BIGSERIAL PRIMARY KEY,
    employee_id     INTEGER REFERENCES bdi_employees(id) ON DELETE SET NULL,
    employee_user   VARCHAR(100),
    client_code     VARCHAR(50),
    status          VARCHAR(20) NOT NULL,              -- 'SUCCESS', 'DENIED', 'FAILED'
    ip_address      VARCHAR(64),
    machine_name    VARCHAR(150),
    details         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bdi_logs_created_at ON bdi_access_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bdi_logs_employee   ON bdi_access_logs (employee_id);