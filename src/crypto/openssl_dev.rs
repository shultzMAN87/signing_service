//! Тестовый провайдер: OpenSSL 3 + gost-engine. Только для разработки и
//! автотестов (cargo feature `openssl-dev`), в Docker-сборку не входит.
use super::{Hasher, KeyHandle, OpenedKey, Provider};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::{Hasher as OHasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::X509;
use std::ffi::CString;
use zeroize::Zeroizing;

pub struct OpensslDev;

fn nid(name: &str) -> AppResult<Nid> {
    let c = CString::new(name).unwrap();
    let n = unsafe { openssl_sys::OBJ_sn2nid(c.as_ptr()) };
    if n == 0 {
        return Err(AppError::new("crypto_error", format!("OpenSSL не знает {name} — не загружен gost-engine?")));
    }
    Ok(Nid::from_raw(n))
}

fn md(oid: &str) -> AppResult<MessageDigest> {
    let name = match oid {
        crate::cert::STREEBOG256 => "md_gost12_256",
        crate::cert::STREEBOG512 => "md_gost12_512",
        _ => return Err(AppError::new("not_gost", "Неизвестный алгоритм хэширования")),
    };
    MessageDigest::from_name(name).ok_or_else(|| AppError::new("crypto_error", "Нет Стрибога: не загружен gost-engine"))
}

fn ce(e: openssl::error::ErrorStack) -> AppError {
    AppError::new("crypto_error", e.to_string())
}

impl OpensslDev {
    pub fn load(cfg: &Config) -> AppResult<Self> {
        // Конфиг с ГОСТ-движком должен быть загружен до первой инициализации OpenSSL.
        std::env::set_var("OPENSSL_CONF", &cfg.openssl_conf);
        openssl::init();
        nid("md_gost12_256")?;
        Ok(Self)
    }
}

struct H(OHasher);
impl Hasher for H {
    fn update(&mut self, data: &[u8]) -> AppResult<()> {
        self.0.update(data).map_err(ce)
    }
    fn finish(mut self: Box<Self>) -> AppResult<Vec<u8>> {
        Ok(self.0.finish().map_err(ce)?.to_vec())
    }
}

impl Provider for OpensslDev {
    fn name(&self) -> &'static str {
        "openssl-dev"
    }
    fn hasher(&self, digest_oid: &str) -> AppResult<Box<dyn Hasher>> {
        Ok(Box::new(H(OHasher::new(md(digest_oid)?).map_err(ce)?)))
    }
    fn open_pfx(&self, pfx: &[u8], pin: &str) -> AppResult<OpenedKey> {
        let p = Pkcs12::from_der(pfx).map_err(|_| AppError::new("invalid_container", "Не PKCS#12"))?;
        let parsed = p.parse2(pin).map_err(|e| {
            let s = e.to_string().to_lowercase();
            if s.contains("mac verify") || s.contains("invalid password") {
                AppError::new("invalid_pin", "Неверный PIN")
            } else {
                AppError::new("invalid_container", format!("Не удалось открыть PFX: {e}"))
            }
        })?;
        let (pkey, cert) = match (parsed.pkey, parsed.cert) {
            (Some(k), Some(c)) => (k, c),
            _ => return Err(AppError::new("invalid_container", "В PFX нет ключа или сертификата")),
        };
        if !cert.public_key().map_err(ce)?.public_eq(&pkey) {
            return Err(AppError::new("key_mismatch", "Ключ не соответствует сертификату"));
        }
        let chain = parsed.ca.map(|s| s.iter().filter_map(|c| c.to_der().ok()).collect()).unwrap_or_default();
        let cert_der = cert.to_der().map_err(ce)?;
        Ok(OpenedKey { key: Box::new(OKey { pkey, cert }), cert_der, chain })
    }
    fn verify_cert_signature(&self, cert: &[u8], issuer: &[u8]) -> AppResult<bool> {
        let c = X509::from_der(cert).map_err(ce)?;
        let i = X509::from_der(issuer).map_err(ce)?;
        let pk = i.public_key().map_err(ce)?;
        Ok(c.verify(&pk).unwrap_or(false))
    }
    fn verify_detached(&self, cms: &[u8], content: &[u8]) -> AppResult<bool> {
        let mut c = CmsContentInfo::from_der(cms).map_err(ce)?;
        Ok(c.verify(None, None, Some(content), None, CMSOptions::NO_SIGNER_CERT_VERIFY | CMSOptions::BINARY).is_ok())
    }
    fn encrypt(&self, data: &[u8], recipients: &[Vec<u8>], cipher: &str) -> AppResult<Vec<u8>> {
        let mut st = Stack::new().map_err(ce)?;
        for r in recipients {
            st.push(X509::from_der(r).map_err(|_| AppError::new("bad_request", "Сертификат получателя"))?).map_err(ce)?;
        }
        let name = match cipher {
            "kuznyechik" | "" | "default" => "kuznyechik-ctr-acpkm",
            "magma" => "magma-ctr-acpkm",
            "gost89" => "gost89",
            _ => return Err(AppError::new("bad_request", "cipher: kuznyechik | magma | gost89")),
        };
        let c = Cipher::from_nid(nid(name)?).ok_or_else(|| AppError::new("crypto_error", "Нет шифра"))?;
        // Как `openssl cms -encrypt`: получатели добавляются с CMS_KEY_PARAM, иначе
        // gost-engine отвечает «ctrl failure» на KeyTransport ГОСТ.
        unsafe {
            use foreign_types::{ForeignType, ForeignTypeRef};
            const BINARY: u32 = 0x80;
            const PARTIAL: u32 = 0x4000;
            const KEY_PARAM: u32 = 0x40000;
            let bio = openssl_sys::BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as i32);
            let cms = openssl_sys::CMS_encrypt(std::ptr::null_mut(), bio, c.as_ptr(), BINARY | PARTIAL);
            openssl_sys::BIO_free_all(bio);
            if cms.is_null() {
                return Err(ce(openssl::error::ErrorStack::get()));
            }
            let cms = CmsContentInfo::from_ptr(cms);
            for x in st.iter() {
                if CMS_add1_recipient_cert(cms.as_ptr(), x.as_ptr(), BINARY | PARTIAL | KEY_PARAM).is_null() {
                    return Err(ce(openssl::error::ErrorStack::get()));
                }
            }
            let bio = openssl_sys::BIO_new_mem_buf(data.as_ptr() as *const _, data.len() as i32);
            let ok = CMS_final(cms.as_ptr(), bio, std::ptr::null_mut(), BINARY);
            openssl_sys::BIO_free_all(bio);
            if ok != 1 {
                return Err(ce(openssl::error::ErrorStack::get()));
            }
            cms.to_der().map_err(ce)
        }
    }
}

extern "C" {
    fn CMS_final(cms: *mut openssl_sys::CMS_ContentInfo, data: *mut openssl_sys::BIO, dcont: *mut openssl_sys::BIO, flags: u32) -> i32;
    fn CMS_add1_recipient_cert(cms: *mut openssl_sys::CMS_ContentInfo, x: *mut openssl_sys::X509, flags: u32) -> *mut std::ffi::c_void;
}

struct OKey {
    pkey: PKey<Private>,
    cert: X509,
}

impl KeyHandle for OKey {
    fn sign_digest(&self, digest: &[u8]) -> AppResult<Vec<u8>> {
        let mut ctx = PkeyCtx::new(&self.pkey).map_err(ce)?;
        ctx.sign_init().map_err(ce)?;
        let mut sig = Vec::new();
        ctx.sign_to_vec(digest, &mut sig).map_err(ce)?;
        Ok(sig)
    }
    fn decrypt(&self, cms: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        let c = CmsContentInfo::from_der(cms).map_err(|_| AppError::new("decrypt_failed", "Не CMS"))?;
        c.decrypt(&self.pkey, &self.cert)
            .map(Zeroizing::new)
            .map_err(|_| AppError::new("decrypt_failed", "Данные зашифрованы не на этот ключ или повреждены"))
    }
    fn export_pfx(&self, pin: &str) -> AppResult<Vec<u8>> {
        let mut b = Pkcs12::builder();
        b.name("esign").pkey(&self.pkey).cert(&self.cert);
        b.key_algorithm(nid("gost89")?).cert_algorithm(nid("gost89")?);
        b.mac_md(md(crate::cert::STREEBOG256)?);
        b.build2(pin).map_err(ce)?.to_der().map_err(ce)
    }
}
