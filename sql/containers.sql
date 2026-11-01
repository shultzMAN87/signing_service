-- Отдельная БД (другой инстанс/учётка/бэкапы): только шифротексты контейнеров.
CREATE TABLE IF NOT EXISTS containers (
    thumbprint   text PRIMARY KEY,
    ciphertext   bytea NOT NULL,   -- nonce || AES-256-GCM(DEK, PFX с PIN сервиса), AAD = отпечаток
    dek_wrapped  text  NOT NULL,   -- DEK, зашифрованный в KMS (ключ esign-container)
    fmt          text  NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Временная область для шага 1 загрузки (контейнер пришёл, PIN ещё нет).
CREATE TABLE IF NOT EXISTS staged (
    upload_id    uuid PRIMARY KEY,
    ciphertext   bytea NOT NULL,   -- AAD = upload_id
    dek_wrapped  text  NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
