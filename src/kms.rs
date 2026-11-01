//! KMS с интерфейсом Vault Transit + envelope-шифрование контейнеров.
//! * vault — HashiCorp Vault Transit (ключи derived=true, context = отпечаток);
//! * local — локальный эмулятор для автотестов (формат `vault:vN:...`).
use crate::error::{AppError, AppResult};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

#[async_trait]
pub trait Kms: Send + Sync {
    async fn encrypt(&self, key: &str, plaintext: &[u8], context: &str) -> AppResult<String>;
    async fn decrypt(&self, key: &str, ciphertext: &str, context: &str) -> AppResult<Zeroizing<Vec<u8>>>;
    async fn ensure_key(&self, key: &str) -> AppResult<()>;

    /// Самопроверка при старте: пробное шифрование и расшифровка с контекстом.
    async fn self_check(&self, key: &str) -> AppResult<()> {
        let ct = self.encrypt(key, b"esign self-check", "self-check").await?;
        let pt = self.decrypt(key, &ct, "self-check").await?;
        if pt.as_slice() != b"esign self-check" {
            return Err(AppError::new("dependency_unavailable", format!("KMS: ключ {key} вернул неверные данные")));
        }
        Ok(())
    }
}

fn unavailable(e: impl std::fmt::Display) -> AppError {
    tracing::error!(error = %e, "kms");
    AppError::new("dependency_unavailable", "KMS (Vault) недоступен")
}

pub struct VaultTransit {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl VaultTransit {
    pub fn new(addr: &str, token: &str, mount: &str) -> Self {
        Self {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().unwrap(),
            base: format!("{}/v1/{}", addr.trim_end_matches('/'), mount),
            token: token.to_string(),
        }
    }
    async fn post(&self, path: &str, body: serde_json::Value) -> AppResult<serde_json::Value> {
        let r = self.http.post(format!("{}{}", self.base, path)).header("X-Vault-Token", &self.token).json(&body).send().await.map_err(unavailable)?;
        let status = r.status();
        let v: serde_json::Value = r.json().await.unwrap_or_default();
        if !status.is_success() {
            let msg = v["errors"].to_string();
            tracing::error!(%status, path, errors = %msg, "vault");
            return Err(AppError::new("dependency_unavailable", format!("Vault отказал ({status}) на {path}: {msg}")));
        }
        Ok(v)
    }
}

#[async_trait]
impl Kms for VaultTransit {
    async fn encrypt(&self, key: &str, plaintext: &[u8], context: &str) -> AppResult<String> {
        let v = self.post(&format!("/encrypt/{key}"), json!({"plaintext": B64.encode(plaintext), "context": B64.encode(context)})).await?;
        v["data"]["ciphertext"].as_str().map(String::from).ok_or_else(|| unavailable("нет ciphertext"))
    }
    async fn decrypt(&self, key: &str, ciphertext: &str, context: &str) -> AppResult<Zeroizing<Vec<u8>>> {
        let v = self.post(&format!("/decrypt/{key}"), json!({"ciphertext": ciphertext, "context": B64.encode(context)})).await?;
        let p = v["data"]["plaintext"].as_str().ok_or_else(|| unavailable("нет plaintext"))?;
        Ok(Zeroizing::new(B64.decode(p).map_err(unavailable)?))
    }
    async fn ensure_key(&self, _key: &str) -> AppResult<()> {
        // Ключи создаёт vault-init: у токена сервиса прав на создание нет (и не должно быть).
        Ok(())
    }
}

/// Локальный эмулятор Transit: мастер-ключи в файле (только для тестов!).
pub struct LocalKms {
    file: std::path::PathBuf,
    keys: Mutex<HashMap<String, Vec<String>>>,
}

impl LocalKms {
    pub fn new(dir: &str) -> AppResult<Self> {
        std::fs::create_dir_all(dir).map_err(|e| AppError::new("crypto_error", e.to_string()))?;
        let file = std::path::Path::new(dir).join("keys.json");
        let keys = std::fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        Ok(Self { file, keys: Mutex::new(keys) })
    }
    fn key(&self, name: &str, version: Option<usize>) -> AppResult<(usize, Zeroizing<Vec<u8>>)> {
        let mut g = self.keys.lock().unwrap();
        let versions = g.entry(name.to_string()).or_default();
        if versions.is_empty() {
            let mut k = [0u8; 32];
            rand::rng().fill_bytes(&mut k);
            versions.push(B64.encode(k));
            let data = serde_json::to_string(&*g).unwrap();
            write_private(&self.file, data.as_bytes());
        }
        let versions = &g[name];
        let v = version.unwrap_or(versions.len());
        let k = versions.get(v - 1).ok_or_else(|| AppError::new("dependency_unavailable", "Нет версии ключа KMS"))?;
        Ok((v, Zeroizing::new(B64.decode(k).unwrap())))
    }
    fn derive(master: &[u8], context: &str) -> Zeroizing<[u8; 32]> {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(context.as_bytes(), &mut *out).unwrap();
        out
    }
}

fn write_private(path: &std::path::Path, data: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp) {
        let _ = f.write_all(data);
        let _ = std::fs::rename(&tmp, path);
    }
}

#[async_trait]
impl Kms for LocalKms {
    async fn encrypt(&self, key: &str, plaintext: &[u8], context: &str) -> AppResult<String> {
        let (v, master) = self.key(key, None)?;
        let k = Self::derive(&master, context);
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let ct = Aes256Gcm::new_from_slice(&*k).unwrap().encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
        Ok(format!("vault:v{v}:{}", B64.encode([nonce.as_slice(), &ct].concat())))
    }
    async fn decrypt(&self, key: &str, ciphertext: &str, context: &str) -> AppResult<Zeroizing<Vec<u8>>> {
        let bad = || AppError::new("dependency_unavailable", "KMS: неверный шифротекст или контекст");
        let mut it = ciphertext.splitn(3, ':');
        let (_, ver, body) = (it.next(), it.next().ok_or_else(bad)?, it.next().ok_or_else(bad)?);
        let v: usize = ver.trim_start_matches('v').parse().map_err(|_| bad())?;
        let (_, master) = self.key(key, Some(v))?;
        let raw = B64.decode(body).map_err(|_| bad())?;
        if raw.len() < 12 {
            return Err(bad());
        }
        let k = Self::derive(&master, context);
        Aes256Gcm::new_from_slice(&*k).unwrap().decrypt(Nonce::from_slice(&raw[..12]), &raw[12..]).map(Zeroizing::new).map_err(|_| bad())
    }
    async fn ensure_key(&self, key: &str) -> AppResult<()> {
        self.key(key, None).map(|_| ())
    }
}

/// Контейнер шифруется своим DEK (AES-256-GCM, AAD = контекст), DEK — в KMS.
pub async fn seal(kms: &dyn Kms, kek: &str, plaintext: &[u8], context: &str) -> AppResult<(Vec<u8>, String)> {
    let mut dek = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *dek);
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = Aes256Gcm::new_from_slice(&*dek)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: context.as_bytes() })
        .unwrap();
    let wrapped = kms.encrypt(kek, &*dek, context).await?;
    Ok(([nonce.as_slice(), &ct].concat(), wrapped))
}

pub async fn unseal(kms: &dyn Kms, kek: &str, ct: &[u8], wrapped: &str, context: &str) -> AppResult<Zeroizing<Vec<u8>>> {
    let dek = kms.decrypt(kek, wrapped, context).await?;
    if ct.len() < 12 || dek.len() != 32 {
        return Err(AppError::new("dependency_unavailable", "Повреждён шифротекст контейнера"));
    }
    Aes256Gcm::new_from_slice(&dek)
        .unwrap()
        .decrypt(Nonce::from_slice(&ct[..12]), Payload { msg: &ct[12..], aad: context.as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| AppError::new("dependency_unavailable", "Шифротекст контейнера повреждён или подменён"))
}

pub fn make(cfg: &crate::config::Config) -> AppResult<std::sync::Arc<dyn Kms>> {
    match cfg.kms.as_str() {
        "vault" => Ok(std::sync::Arc::new(VaultTransit::new(&cfg.vault_addr, &cfg.vault_token, &cfg.vault_mount))),
        "local" => Ok(std::sync::Arc::new(LocalKms::new(&cfg.kms_dir)?)),
        o => Err(AppError::new("crypto_error", format!("Неизвестный KMS {o}"))),
    }
}
