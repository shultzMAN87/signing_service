-- БД метаданных: ключи, права, зашифрованный PIN, заявки, аудит.
-- Контейнеров здесь нет.
CREATE TABLE IF NOT EXISTS keys (
    thumbprint      text PRIMARY KEY,
    key_type        text NOT NULL CHECK (key_type IN ('organization', 'employee')),
    owner_login     text,
    subject         text NOT NULL,
    issuer          text NOT NULL,
    serial          text NOT NULL,
    not_before      timestamptz NOT NULL,
    not_after       timestamptz NOT NULL,
    key_alg         text NOT NULL,
    cert_der        bytea NOT NULL,
    status          text NOT NULL CHECK (status IN ('active', 'blocked', 'deleted', 'purged')),
    pin_ct          text,              -- PIN, зашифрованный в KMS (ключ esign-pin, context = отпечаток)
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    pin_changed_at  timestamptz,
    deleted_at      timestamptz,
    purge_after     timestamptz,
    last_used_at    timestamptz
);

-- Права систем на ключ: отдельно sign и decrypt.
CREATE TABLE IF NOT EXISTS key_clients (
    thumbprint  text REFERENCES keys(thumbprint) ON DELETE CASCADE,
    client_id   text NOT NULL,
    can_sign    boolean NOT NULL DEFAULT true,
    can_decrypt boolean NOT NULL DEFAULT false,
    PRIMARY KEY (thumbprint, client_id)
);

CREATE TABLE IF NOT EXISTS uploads (
    upload_id    uuid PRIMARY KEY,
    created_by   text NOT NULL,
    key_type     text NOT NULL,
    owner_login  text,
    clients      jsonb NOT NULL DEFAULT '[]',
    status       text NOT NULL DEFAULT 'pending',   -- pending | done | failed | expired
    attempts     int  NOT NULL DEFAULT 0,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    thumbprint   text
);

CREATE TABLE IF NOT EXISTS emergency (
    scope       text PRIMARY KEY,                  -- 'all' или 'client:<id>'
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Журнал только на добавление.
CREATE TABLE IF NOT EXISTS audit (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    request_id  text,
    actor       text,
    op          text NOT NULL,
    thumbprint  text,
    doc_hash    text,
    details     jsonb,
    result      text NOT NULL,
    error_code  text
);
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit is append-only'; END $$;
DROP TRIGGER IF EXISTS audit_no_change ON audit;
CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE ON audit
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
