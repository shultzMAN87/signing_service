//! Интерфейс криптопровайдера. Все вызовы блокирующие — сервис вызывает их
//! через `spawn_blocking`.
use crate::error::AppResult;
use zeroize::Zeroizing;

pub mod cryptopro;
#[cfg(feature = "openssl-dev")]
pub mod openssl_dev;

pub trait Hasher: Send {
    fn update(&mut self, data: &[u8]) -> AppResult<()>;
    fn finish(self: Box<Self>) -> AppResult<Vec<u8>>;
}

/// Открытый закрытый ключ. Drop освобождает ключ (и удаляет временный контейнер).
pub trait KeyHandle: Send + Sync {
    /// Подпись хэша. Порядок байт — «как вернул провайдер»; сервис при загрузке
    /// ключа проверяет пробной CMS-подписью, нужно ли его переворачивать.
    fn sign_digest(&self, digest: &[u8]) -> AppResult<Vec<u8>>;
    /// Расшифровка CMS EnvelopedData, зашифрованной на сертификат этого ключа.
    fn decrypt(&self, cms: &[u8]) -> AppResult<Zeroizing<Vec<u8>>>;
    /// PFX с этим ключом и сертификатом под новым PIN.
    fn export_pfx(&self, pin: &str) -> AppResult<Vec<u8>>;
}

pub struct OpenedKey {
    pub key: Box<dyn KeyHandle>,
    pub cert_der: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn hasher(&self, digest_oid: &str) -> AppResult<Box<dyn Hasher>>;
    fn digest(&self, digest_oid: &str, data: &[u8]) -> AppResult<Vec<u8>> {
        let mut h = self.hasher(digest_oid)?;
        h.update(data)?;
        h.finish()
    }
    /// Открыть PFX (ключ остаётся только в памяти провайдера / временном контейнере).
    fn open_pfx(&self, pfx: &[u8], pin: &str) -> AppResult<OpenedKey>;
    /// Подписан ли `cert` ключом `issuer`.
    fn verify_cert_signature(&self, cert: &[u8], issuer: &[u8]) -> AppResult<bool>;
    /// Проверка отделённой CMS-подписи (без проверки цепочки).
    fn verify_detached(&self, cms: &[u8], content: &[u8]) -> AppResult<bool>;
    /// CMS EnvelopedData на сертификаты получателей.
    fn encrypt(&self, data: &[u8], recipients: &[Vec<u8>], cipher: &str) -> AppResult<Vec<u8>>;
}

pub fn make(cfg: &crate::config::Config) -> AppResult<std::sync::Arc<dyn Provider>> {
    match cfg.provider.as_str() {
        "cryptopro" => Ok(std::sync::Arc::new(cryptopro::CryptoPro::load(cfg)?)),
        #[cfg(feature = "openssl-dev")]
        "openssl-dev" => Ok(std::sync::Arc::new(openssl_dev::OpensslDev::load(cfg)?)),
        other => Err(crate::error::AppError::new("crypto_error", format!("Неизвестный провайдер {other}"))),
    }
}
