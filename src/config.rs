//! Настройки — переменные окружения ESIGN_*.
use std::collections::HashMap;
use std::env;

#[derive(Clone, Debug)]
pub struct Client {
    pub id: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub meta_dsn: String,
    pub store_dsn: String,

    /// cryptopro | openssl-dev
    pub provider: String,
    pub cryptopro_lib_dir: String,
    pub cryptopro_wchar_size: usize,
    pub cryptopro_keys_dir: String,
    pub encrypt_oid: String,
    #[allow(dead_code)]
    pub openssl_conf: String,

    /// vault | local
    pub kms: String,
    pub vault_addr: String,
    pub vault_token: String,
    pub vault_mount: String,
    pub kms_dir: String,
    pub kek_container: String,
    pub kek_pin: String,

    pub transport_pfx: String,
    pub transport_pin: String,
    pub trust_ca: String,
    pub test_mode: bool,

    pub clients: HashMap<String, Client>,

    pub upload_ttl_min: i64,
    pub pin_attempts: i32,
    pub retention_days: i64,
    pub max_container: usize,
    pub max_file: usize,

    pub cache_max: u64,
    pub cache_idle_sec: u64,
    pub cache_ttl_sec: u64,

    pub sign_ext: Vec<String>,
    pub enc_ext: Vec<String>,

    /// Запросов в секунду на систему (0 — без ограничения)
    pub rate_per_client: u32,
    /// Запросов в секунду на ключ (0 — без ограничения)
    pub rate_per_key: u32,
}

fn e(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn n<T: std::str::FromStr>(name: &str, default: T) -> T {
    env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

impl Config {
    pub fn from_env() -> anyhow_lite::Result<Self> {
        let clients_raw = match env::var("ESIGN_CLIENTS") {
            Ok(v) => v,
            Err(_) => std::fs::read_to_string(e("ESIGN_CLIENTS_FILE", "clients.json")).unwrap_or_else(|_| "{}".into()),
        };
        let parsed: HashMap<String, serde_json::Value> = serde_json::from_str(&clients_raw)
            .map_err(|err| anyhow_lite::Error(format!("ESIGN_CLIENTS: {err}")))?;
        let clients = parsed
            .into_iter()
            .map(|(token, v)| {
                let id = v["id"].as_str().unwrap_or_default().to_string();
                let roles = v["roles"].as_array().map(|a| a.iter().filter_map(|r| r.as_str().map(String::from)).collect()).unwrap_or_default();
                (token, Client { id, roles })
            })
            .collect();
        let list = |name: &str, d: &str| e(name, d).split(',').map(|s| s.trim().trim_start_matches('.').to_lowercase()).filter(|s| !s.is_empty()).collect();
        Ok(Self {
            listen: e("ESIGN_LISTEN", "0.0.0.0:8800"),
            meta_dsn: e("ESIGN_META_DSN", "postgresql://esign_meta:meta_pw@localhost/esign_meta"),
            store_dsn: e("ESIGN_STORE_DSN", "postgresql://esign_store:store_pw@localhost/esign_containers"),
            provider: e("ESIGN_PROVIDER", "cryptopro"),
            cryptopro_lib_dir: e("ESIGN_CRYPTOPRO_LIB", "/opt/cprocsp/lib/amd64"),
            cryptopro_wchar_size: n("ESIGN_CRYPTOPRO_WCHAR", 4usize),
            cryptopro_keys_dir: e("ESIGN_CRYPTOPRO_KEYS_DIR", ""),
            // ГОСТ 28147-89 по умолчанию: поддерживается всеми версиями КриптоПро.
            // «Кузнечик» CTR-ACPKM (КриптоПро 5.0 R2+): 1.2.643.7.1.1.5.2.2
            encrypt_oid: e("ESIGN_ENCRYPT_OID", "1.2.643.2.2.21"),
            openssl_conf: e("ESIGN_OPENSSL_CONF", "gost.cnf"),
            kms: e("ESIGN_KMS", "vault"),
            vault_addr: e("VAULT_ADDR", "http://127.0.0.1:8200"),
            vault_token: e("VAULT_TOKEN", ""),
            vault_mount: e("ESIGN_VAULT_MOUNT", "transit"),
            kms_dir: e("ESIGN_KMS_DIR", "var/kms"),
            kek_container: e("ESIGN_KEK_CONTAINER", "esign-container"),
            kek_pin: e("ESIGN_KEK_PIN", "esign-pin"),
            transport_pfx: e("ESIGN_TRANSPORT_PFX", ""),
            transport_pin: e("ESIGN_TRANSPORT_PIN", ""),
            trust_ca: e("ESIGN_TRUST_CA", ""),
            test_mode: e("ESIGN_TEST_MODE", "1") == "1",
            clients,
            upload_ttl_min: n("ESIGN_UPLOAD_TTL_MIN", 15),
            pin_attempts: n("ESIGN_PIN_ATTEMPTS", 5),
            retention_days: n("ESIGN_RETENTION_DAYS", 7),
            max_container: n("ESIGN_MAX_CONTAINER", 1024 * 1024),
            max_file: n("ESIGN_MAX_FILE", 100 * 1024 * 1024),
            cache_max: n("ESIGN_CACHE_MAX", 500),
            cache_idle_sec: n("ESIGN_CACHE_IDLE_SEC", 1800),
            cache_ttl_sec: n("ESIGN_CACHE_TTL_SEC", 8 * 3600),
            sign_ext: list("ESIGN_SIGN_EXT", "sgn,sig,p7s,sign,p7m"),
            enc_ext: list("ESIGN_ENC_EXT", "p7m,enc"),
            rate_per_client: n("ESIGN_RATE_PER_CLIENT", 0),
            rate_per_key: n("ESIGN_RATE_PER_KEY", 0),
        })
    }
}

/// Минимальная обёртка ошибки конфигурации без лишних зависимостей.
pub mod anyhow_lite {
    #[derive(Debug)]
    pub struct Error(pub String);
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}
    pub type Result<T> = std::result::Result<T, Error>;
}
