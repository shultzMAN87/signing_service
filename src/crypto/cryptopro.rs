//! Провайдер КриптоПро CSP 5.0 (Linux) через CryptoAPI: libcapi10.so и libcapi20.so.
//!
//! Библиотеки загружаются динамически (libloading), поэтому сервис собирается
//! без КриптоПро; при старте с ESIGN_PROVIDER=cryptopro они обязательны.
//!
//! Модель работы с ключом:
//! * PFX импортируется PFXImportCertStore в считыватель HDIMAGE пользователя
//!   сервиса. Каталог ключей смонтирован как tmpfs — на диск контейнер не попадает.
//! * Пока ключ в кэше, держится HCRYPTPROV. При вытеснении контекст
//!   освобождается, а временный контейнер удаляется (CRYPT_DELETEKEYSET).
//! * Подпись: CryptCreateHash + CryptSetHashParam(HP_HASHVAL) + CryptSignHash.
//!   CMS собирает сервис (der.rs), порядок байт подписи проверяется пробной
//!   подписью через CryptVerifyDetachedMessageSignature.
//! * Расшифровка: CryptMsg* с нашим HCRYPTPROV (PIN уже введён в контекст).
//!
//! ВНИМАНИЕ: модуль не запускался — в среде разработки не было КриптоПро CSP.
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use super::{Hasher, KeyHandle, OpenedKey, Provider};
use crate::config::Config;
use crate::error::{AppError, AppResult};
use libloading::Library;
use std::ffi::{c_char, c_void, CString};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type BOOL = i32;
type DWORD = u32;
type HCRYPTPROV = usize;
type HCRYPTHASH = usize;
type HCERTSTORE = *mut c_void;
type PCCERT_CONTEXT = *const CERT_CONTEXT;
type HCRYPTMSG = *mut c_void;

#[repr(C)]
struct CRYPT_DATA_BLOB {
    cbData: DWORD,
    pbData: *mut u8,
}

#[repr(C)]
pub struct CERT_CONTEXT {
    dwCertEncodingType: DWORD,
    pbCertEncoded: *mut u8,
    cbCertEncoded: DWORD,
    pCertInfo: *mut c_void,
    hCertStore: HCERTSTORE,
}

#[repr(C)]
struct CRYPT_ALGORITHM_IDENTIFIER {
    pszObjId: *const c_char,
    Parameters: CRYPT_DATA_BLOB,
}

#[repr(C)]
struct CRYPT_ENCRYPT_MESSAGE_PARA {
    cbSize: DWORD,
    dwMsgEncodingType: DWORD,
    hCryptProv: HCRYPTPROV,
    ContentEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER,
    pvEncryptionAuxInfo: *mut c_void,
    dwFlags: DWORD,
    dwInnerContentType: DWORD,
}

#[repr(C)]
struct CRYPT_VERIFY_MESSAGE_PARA {
    cbSize: DWORD,
    dwMsgAndCertEncodingType: DWORD,
    hCryptProv: HCRYPTPROV,
    pfnGetSignerCertificate: *const c_void,
    pvGetArg: *mut c_void,
}

#[repr(C)]
struct CMSG_CTRL_DECRYPT_PARA {
    cbSize: DWORD,
    hCryptProv: HCRYPTPROV,
    dwKeySpec: DWORD,
    dwRecipientIndex: DWORD,
}

#[repr(C)]
struct CRYPT_KEY_PROV_INFO {
    pwszContainerName: *mut c_void,
    pwszProvName: *mut c_void,
    dwProvType: DWORD,
    dwFlags: DWORD,
    cProvParam: DWORD,
    rgProvParam: *mut c_void,
    dwKeySpec: DWORD,
}

const X509_ASN_ENCODING: DWORD = 0x1;
const PKCS_7_ASN_ENCODING: DWORD = 0x10000;
const ENC: DWORD = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
const PROV_GOST_2012_256: DWORD = 80;
const PROV_GOST_2012_512: DWORD = 81;
const CALG_GR3411_2012_256: DWORD = 0x8021;
const CALG_GR3411_2012_512: DWORD = 0x8022;
const CRYPT_VERIFYCONTEXT: DWORD = 0xF000_0000;
const CRYPT_SILENT: DWORD = 0x40;
const CRYPT_DELETEKEYSET: DWORD = 0x10;
const HP_HASHVAL: DWORD = 0x2;
const PP_KEYEXCHANGE_PIN: DWORD = 32;
const PP_SIGNATURE_PIN: DWORD = 33;
const AT_SIGNATURE: DWORD = 2;
const CRYPT_EXPORTABLE: DWORD = 0x1;
const CRYPT_USER_KEYSET: DWORD = 0x1000;
const PKCS12_IMPORT_SILENT: DWORD = 0x40;
const EXPORT_PRIVATE_KEYS: DWORD = 0x4;
const REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY: DWORD = 0x2;
const REPORT_NO_PRIVATE_KEY: DWORD = 0x1;
const CRYPT_ACQUIRE_SILENT_FLAG: DWORD = 0x40;
const CERT_KEY_PROV_INFO_PROP_ID: DWORD = 2;
const CERT_STORE_PROV_MEMORY: usize = 2;
const CERT_STORE_ADD_ALWAYS: DWORD = 4;
const CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB: DWORD = 1;
const CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT: DWORD = 2;
const CMSG_CONTENT_PARAM: DWORD = 2;
const CMSG_RECIPIENT_COUNT_PARAM: DWORD = 17;
const CMSG_CTRL_DECRYPT: DWORD = 2;
const ERROR_INVALID_PASSWORD: u32 = 0x56;
const NTE_BAD_PASSWORD: u32 = 0x8009_0016; // нет в CryptoAPI MS, встречается у КриптоПро как SCARD_W_WRONG_CHV
const SCARD_W_WRONG_CHV: u32 = 0x8010_006B;

macro_rules! sym {
    ($lib:expr, $ty:ty, $($name:literal),+) => {{
        let mut f: Option<$ty> = None;
        $( if f.is_none() { f = unsafe { $lib.get::<$ty>(concat!($name, "\0").as_bytes()).ok().map(|s| *s) }; } )+
        f.ok_or_else(|| AppError::new("crypto_error", concat!("В КриптоПро нет функции ", $($name, " "),+)))?
    }};
}

#[allow(clippy::type_complexity)]
struct Api {
    _l10: Library,
    _l20: Library,
    _ssp: Option<Library>,
    CryptAcquireContextA: unsafe extern "C" fn(*mut HCRYPTPROV, *const c_char, *const c_char, DWORD, DWORD) -> BOOL,
    CryptReleaseContext: unsafe extern "C" fn(HCRYPTPROV, DWORD) -> BOOL,
    CryptSetProvParam: unsafe extern "C" fn(HCRYPTPROV, DWORD, *const u8, DWORD) -> BOOL,
    CryptCreateHash: unsafe extern "C" fn(HCRYPTPROV, DWORD, usize, DWORD, *mut HCRYPTHASH) -> BOOL,
    CryptHashData: unsafe extern "C" fn(HCRYPTHASH, *const u8, DWORD, DWORD) -> BOOL,
    CryptGetHashParam: unsafe extern "C" fn(HCRYPTHASH, DWORD, *mut u8, *mut DWORD, DWORD) -> BOOL,
    CryptSetHashParam: unsafe extern "C" fn(HCRYPTHASH, DWORD, *const u8, DWORD) -> BOOL,
    CryptSignHashA: unsafe extern "C" fn(HCRYPTHASH, DWORD, *const c_char, DWORD, *mut u8, *mut DWORD) -> BOOL,
    CryptDestroyHash: unsafe extern "C" fn(HCRYPTHASH) -> BOOL,
    PFXImportCertStore: unsafe extern "C" fn(*mut CRYPT_DATA_BLOB, *const c_void, DWORD) -> HCERTSTORE,
    PFXExportCertStoreEx: unsafe extern "C" fn(HCERTSTORE, *mut CRYPT_DATA_BLOB, *const c_void, *mut c_void, DWORD) -> BOOL,
    CertOpenStore: unsafe extern "C" fn(usize, DWORD, HCRYPTPROV, DWORD, *const c_void) -> HCERTSTORE,
    CertCloseStore: unsafe extern "C" fn(HCERTSTORE, DWORD) -> BOOL,
    CertEnumCertificatesInStore: unsafe extern "C" fn(HCERTSTORE, PCCERT_CONTEXT) -> PCCERT_CONTEXT,
    CertDuplicateCertificateContext: unsafe extern "C" fn(PCCERT_CONTEXT) -> PCCERT_CONTEXT,
    CertFreeCertificateContext: unsafe extern "C" fn(PCCERT_CONTEXT) -> BOOL,
    CertGetCertificateContextProperty: unsafe extern "C" fn(PCCERT_CONTEXT, DWORD, *mut c_void, *mut DWORD) -> BOOL,
    CertCreateCertificateContext: unsafe extern "C" fn(DWORD, *const u8, DWORD) -> PCCERT_CONTEXT,
    CertAddCertificateContextToStore: unsafe extern "C" fn(HCERTSTORE, PCCERT_CONTEXT, DWORD, *mut PCCERT_CONTEXT) -> BOOL,
    CryptAcquireCertificatePrivateKey: unsafe extern "C" fn(PCCERT_CONTEXT, DWORD, *mut c_void, *mut HCRYPTPROV, *mut DWORD, *mut BOOL) -> BOOL,
    CryptEncryptMessage: unsafe extern "C" fn(*const CRYPT_ENCRYPT_MESSAGE_PARA, DWORD, *const PCCERT_CONTEXT, *const u8, DWORD, *mut u8, *mut DWORD) -> BOOL,
    CryptVerifyDetachedMessageSignature: unsafe extern "C" fn(*const CRYPT_VERIFY_MESSAGE_PARA, DWORD, *const u8, DWORD, DWORD, *const *const u8, *const DWORD, *mut PCCERT_CONTEXT) -> BOOL,
    CryptVerifyCertificateSignatureEx: unsafe extern "C" fn(HCRYPTPROV, DWORD, DWORD, *mut c_void, DWORD, *mut c_void, DWORD, *mut c_void) -> BOOL,
    CryptMsgOpenToDecode: unsafe extern "C" fn(DWORD, DWORD, DWORD, HCRYPTPROV, *mut c_void, *mut c_void) -> HCRYPTMSG,
    CryptMsgUpdate: unsafe extern "C" fn(HCRYPTMSG, *const u8, DWORD, BOOL) -> BOOL,
    CryptMsgGetParam: unsafe extern "C" fn(HCRYPTMSG, DWORD, DWORD, *mut c_void, *mut DWORD) -> BOOL,
    CryptMsgControl: unsafe extern "C" fn(HCRYPTMSG, DWORD, DWORD, *const c_void) -> BOOL,
    CryptMsgClose: unsafe extern "C" fn(HCRYPTMSG) -> BOOL,
    GetLastError: Option<unsafe extern "C" fn() -> DWORD>,
}

unsafe impl Send for Api {}
unsafe impl Sync for Api {}

impl Api {
    fn last_error(&self) -> u32 {
        self.GetLastError.map(|f| unsafe { f() }).unwrap_or(0)
    }
    fn err(&self, code: &'static str, what: &str) -> AppError {
        AppError::new(code, format!("{what}: 0x{:08X}", self.last_error()))
    }
}

pub struct CryptoPro {
    api: Arc<Api>,
    wchar: usize,
    encrypt_oid: CString,
    verify_prov: Mutex<[HCRYPTPROV; 2]>,
}

impl CryptoPro {
    pub fn load(cfg: &Config) -> AppResult<Self> {
        let dir = std::path::Path::new(&cfg.cryptopro_lib_dir);
        let open = |n: &str| unsafe { Library::new(dir.join(n)) }
            .map_err(|e| AppError::new("crypto_error", format!("Не загружена {n} из {}: {e}", dir.display())));
        let l10 = open("libcapi10.so")?;
        let l20 = open("libcapi20.so")?;
        let ssp = open("libssp.so").ok();
        let last_err = unsafe {
            l10.get::<unsafe extern "C" fn() -> DWORD>(b"GetLastError\0").ok().map(|s| *s)
                .or_else(|| l20.get::<unsafe extern "C" fn() -> DWORD>(b"GetLastError\0").ok().map(|s| *s))
                .or_else(|| ssp.as_ref().and_then(|l| l.get::<unsafe extern "C" fn() -> DWORD>(b"GetLastError\0").ok().map(|s| *s)))
        };
        let api = Api {
            CryptAcquireContextA: sym!(l10, unsafe extern "C" fn(*mut HCRYPTPROV, *const c_char, *const c_char, DWORD, DWORD) -> BOOL, "CryptAcquireContextA", "CryptAcquireContext"),
            CryptReleaseContext: sym!(l10, unsafe extern "C" fn(HCRYPTPROV, DWORD) -> BOOL, "CryptReleaseContext"),
            CryptSetProvParam: sym!(l10, unsafe extern "C" fn(HCRYPTPROV, DWORD, *const u8, DWORD) -> BOOL, "CryptSetProvParam"),
            CryptCreateHash: sym!(l10, unsafe extern "C" fn(HCRYPTPROV, DWORD, usize, DWORD, *mut HCRYPTHASH) -> BOOL, "CryptCreateHash"),
            CryptHashData: sym!(l10, unsafe extern "C" fn(HCRYPTHASH, *const u8, DWORD, DWORD) -> BOOL, "CryptHashData"),
            CryptGetHashParam: sym!(l10, unsafe extern "C" fn(HCRYPTHASH, DWORD, *mut u8, *mut DWORD, DWORD) -> BOOL, "CryptGetHashParam"),
            CryptSetHashParam: sym!(l10, unsafe extern "C" fn(HCRYPTHASH, DWORD, *const u8, DWORD) -> BOOL, "CryptSetHashParam"),
            CryptSignHashA: sym!(l10, unsafe extern "C" fn(HCRYPTHASH, DWORD, *const c_char, DWORD, *mut u8, *mut DWORD) -> BOOL, "CryptSignHashA", "CryptSignHash"),
            CryptDestroyHash: sym!(l10, unsafe extern "C" fn(HCRYPTHASH) -> BOOL, "CryptDestroyHash"),
            PFXImportCertStore: sym!(l20, unsafe extern "C" fn(*mut CRYPT_DATA_BLOB, *const c_void, DWORD) -> HCERTSTORE, "PFXImportCertStore"),
            PFXExportCertStoreEx: sym!(l20, unsafe extern "C" fn(HCERTSTORE, *mut CRYPT_DATA_BLOB, *const c_void, *mut c_void, DWORD) -> BOOL, "PFXExportCertStoreEx"),
            CertOpenStore: sym!(l20, unsafe extern "C" fn(usize, DWORD, HCRYPTPROV, DWORD, *const c_void) -> HCERTSTORE, "CertOpenStore"),
            CertCloseStore: sym!(l20, unsafe extern "C" fn(HCERTSTORE, DWORD) -> BOOL, "CertCloseStore"),
            CertEnumCertificatesInStore: sym!(l20, unsafe extern "C" fn(HCERTSTORE, PCCERT_CONTEXT) -> PCCERT_CONTEXT, "CertEnumCertificatesInStore"),
            CertDuplicateCertificateContext: sym!(l20, unsafe extern "C" fn(PCCERT_CONTEXT) -> PCCERT_CONTEXT, "CertDuplicateCertificateContext"),
            CertFreeCertificateContext: sym!(l20, unsafe extern "C" fn(PCCERT_CONTEXT) -> BOOL, "CertFreeCertificateContext"),
            CertGetCertificateContextProperty: sym!(l20, unsafe extern "C" fn(PCCERT_CONTEXT, DWORD, *mut c_void, *mut DWORD) -> BOOL, "CertGetCertificateContextProperty"),
            CertCreateCertificateContext: sym!(l20, unsafe extern "C" fn(DWORD, *const u8, DWORD) -> PCCERT_CONTEXT, "CertCreateCertificateContext"),
            CertAddCertificateContextToStore: sym!(l20, unsafe extern "C" fn(HCERTSTORE, PCCERT_CONTEXT, DWORD, *mut PCCERT_CONTEXT) -> BOOL, "CertAddCertificateContextToStore"),
            CryptAcquireCertificatePrivateKey: sym!(l20, unsafe extern "C" fn(PCCERT_CONTEXT, DWORD, *mut c_void, *mut HCRYPTPROV, *mut DWORD, *mut BOOL) -> BOOL, "CryptAcquireCertificatePrivateKey"),
            CryptEncryptMessage: sym!(l20, unsafe extern "C" fn(*const CRYPT_ENCRYPT_MESSAGE_PARA, DWORD, *const PCCERT_CONTEXT, *const u8, DWORD, *mut u8, *mut DWORD) -> BOOL, "CryptEncryptMessage"),
            CryptVerifyDetachedMessageSignature: sym!(l20, unsafe extern "C" fn(*const CRYPT_VERIFY_MESSAGE_PARA, DWORD, *const u8, DWORD, DWORD, *const *const u8, *const DWORD, *mut PCCERT_CONTEXT) -> BOOL, "CryptVerifyDetachedMessageSignature"),
            CryptVerifyCertificateSignatureEx: sym!(l20, unsafe extern "C" fn(HCRYPTPROV, DWORD, DWORD, *mut c_void, DWORD, *mut c_void, DWORD, *mut c_void) -> BOOL, "CryptVerifyCertificateSignatureEx"),
            CryptMsgOpenToDecode: sym!(l20, unsafe extern "C" fn(DWORD, DWORD, DWORD, HCRYPTPROV, *mut c_void, *mut c_void) -> HCRYPTMSG, "CryptMsgOpenToDecode"),
            CryptMsgUpdate: sym!(l20, unsafe extern "C" fn(HCRYPTMSG, *const u8, DWORD, BOOL) -> BOOL, "CryptMsgUpdate"),
            CryptMsgGetParam: sym!(l20, unsafe extern "C" fn(HCRYPTMSG, DWORD, DWORD, *mut c_void, *mut DWORD) -> BOOL, "CryptMsgGetParam"),
            CryptMsgControl: sym!(l20, unsafe extern "C" fn(HCRYPTMSG, DWORD, DWORD, *const c_void) -> BOOL, "CryptMsgControl"),
            CryptMsgClose: sym!(l20, unsafe extern "C" fn(HCRYPTMSG) -> BOOL, "CryptMsgClose"),
            GetLastError: last_err,
            _l10: l10,
            _l20: l20,
            _ssp: ssp,
        };
        if !cfg.cryptopro_keys_dir.is_empty() {
            // остатки контейнеров после аварийного завершения
            if let Ok(rd) = std::fs::read_dir(&cfg.cryptopro_keys_dir) {
                for e in rd.flatten() {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        Ok(Self {
            api: Arc::new(api),
            wchar: cfg.cryptopro_wchar_size,
            encrypt_oid: CString::new(cfg.encrypt_oid.clone()).unwrap(),
            verify_prov: Mutex::new([0, 0]),
        })
    }

    /// Строка в wchar_t (на Linux у КриптоПро wchar_t = 4 байта).
    fn wide(&self, s: &str) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        if self.wchar == 2 {
            for u in s.encode_utf16().chain(std::iter::once(0)) {
                out.extend_from_slice(&u.to_ne_bytes());
            }
        } else {
            for c in s.chars().chain(std::iter::once('\0')) {
                out.extend_from_slice(&(c as u32).to_ne_bytes());
            }
        }
        out
    }

    fn from_wide(&self, p: *const c_void) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut s = String::new();
        unsafe {
            if self.wchar == 2 {
                let mut q = p as *const u16;
                let mut v = Vec::new();
                while *q != 0 {
                    v.push(*q);
                    q = q.add(1);
                }
                s = String::from_utf16_lossy(&v);
            } else {
                let mut q = p as *const u32;
                while *q != 0 {
                    s.push(char::from_u32(*q).unwrap_or('?'));
                    q = q.add(1);
                }
            }
        }
        s
    }

    fn verify_ctx(&self, prov_type: DWORD) -> AppResult<HCRYPTPROV> {
        let idx = if prov_type == PROV_GOST_2012_512 { 1 } else { 0 };
        let mut g = self.verify_prov.lock().unwrap();
        if g[idx] == 0 {
            let mut h: HCRYPTPROV = 0;
            if unsafe { (self.api.CryptAcquireContextA)(&mut h, null(), null(), prov_type, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) } == 0 {
                return Err(self.api.err("crypto_error", "CryptAcquireContext(VERIFYCONTEXT)"));
            }
            g[idx] = h;
        }
        Ok(g[idx])
    }

    fn cert_ctx(&self, der: &[u8]) -> AppResult<CertCtx> {
        let p = unsafe { (self.api.CertCreateCertificateContext)(X509_ASN_ENCODING, der.as_ptr(), der.len() as DWORD) };
        if p.is_null() {
            return Err(self.api.err("bad_request", "Не удалось прочитать сертификат"));
        }
        Ok(CertCtx { api: self.api.clone(), p })
    }
}

/// RAII для PCCERT_CONTEXT.
struct CertCtx {
    api: Arc<Api>,
    p: PCCERT_CONTEXT,
}
impl Drop for CertCtx {
    fn drop(&mut self) {
        if !self.p.is_null() {
            unsafe { (self.api.CertFreeCertificateContext)(self.p) };
        }
    }
}

fn alg_for_digest(oid: &str) -> AppResult<(DWORD, DWORD)> {
    match oid {
        crate::cert::STREEBOG256 => Ok((PROV_GOST_2012_256, CALG_GR3411_2012_256)),
        crate::cert::STREEBOG512 => Ok((PROV_GOST_2012_512, CALG_GR3411_2012_512)),
        _ => Err(AppError::new("not_gost", "Неизвестный алгоритм хэширования")),
    }
}

struct CpHasher {
    api: Arc<Api>,
    h: HCRYPTHASH,
}
unsafe impl Send for CpHasher {}

impl Hasher for CpHasher {
    fn update(&mut self, data: &[u8]) -> AppResult<()> {
        for chunk in data.chunks(1 << 30) {
            if unsafe { (self.api.CryptHashData)(self.h, chunk.as_ptr(), chunk.len() as DWORD, 0) } == 0 {
                return Err(self.api.err("crypto_error", "CryptHashData"));
            }
        }
        Ok(())
    }
    fn finish(self: Box<Self>) -> AppResult<Vec<u8>> {
        let mut out = vec![0u8; 64];
        let mut n = out.len() as DWORD;
        if unsafe { (self.api.CryptGetHashParam)(self.h, HP_HASHVAL, out.as_mut_ptr(), &mut n, 0) } == 0 {
            return Err(self.api.err("crypto_error", "CryptGetHashParam"));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}
impl Drop for CpHasher {
    fn drop(&mut self) {
        unsafe { (self.api.CryptDestroyHash)(self.h) };
    }
}

impl Provider for CryptoPro {
    fn name(&self) -> &'static str {
        "cryptopro"
    }

    fn hasher(&self, digest_oid: &str) -> AppResult<Box<dyn Hasher>> {
        let (pt, alg) = alg_for_digest(digest_oid)?;
        let prov = self.verify_ctx(pt)?;
        let mut h: HCRYPTHASH = 0;
        if unsafe { (self.api.CryptCreateHash)(prov, alg, 0, 0, &mut h) } == 0 {
            return Err(self.api.err("crypto_error", "CryptCreateHash"));
        }
        Ok(Box::new(CpHasher { api: self.api.clone(), h }))
    }

    fn open_pfx(&self, pfx: &[u8], pin: &str) -> AppResult<OpenedKey> {
        let mut buf = Zeroizing::new(pfx.to_vec());
        let mut blob = CRYPT_DATA_BLOB { cbData: buf.len() as DWORD, pbData: buf.as_mut_ptr() };
        let wpin = self.wide(pin);
        let store = unsafe {
            (self.api.PFXImportCertStore)(&mut blob, wpin.as_ptr() as *const c_void, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | PKCS12_IMPORT_SILENT)
        };
        if store.is_null() {
            let e = self.api.last_error();
            return Err(if e == ERROR_INVALID_PASSWORD || e == NTE_BAD_PASSWORD || e == SCARD_W_WRONG_CHV {
                AppError::new("invalid_pin", "Неверный PIN")
            } else {
                AppError::new("invalid_container", format!("PFXImportCertStore: 0x{e:08X}"))
            });
        }
        // Ищем сертификат, у которого есть закрытый ключ.
        let mut key_cert: PCCERT_CONTEXT = null();
        let mut certs = Vec::new();
        let mut p: PCCERT_CONTEXT = null();
        loop {
            p = unsafe { (self.api.CertEnumCertificatesInStore)(store, p) };
            if p.is_null() {
                break;
            }
            let c = unsafe { &*p };
            let der = unsafe { std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize) }.to_vec();
            let mut n: DWORD = 0;
            let has_key = unsafe { (self.api.CertGetCertificateContextProperty)(p, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut n) } != 0;
            if has_key && key_cert.is_null() {
                key_cert = unsafe { (self.api.CertDuplicateCertificateContext)(p) };
                certs.insert(0, der);
            } else {
                certs.push(der);
            }
        }
        if key_cert.is_null() {
            unsafe { (self.api.CertCloseStore)(store, 0) };
            return Err(AppError::new("invalid_container", "В PFX нет закрытого ключа"));
        }
        let cert_der = certs.remove(0);
        let key = CpKey::new(self, store, key_cert, pin)?;
        Ok(OpenedKey { key: Box::new(key), cert_der, chain: certs })
    }

    fn verify_cert_signature(&self, cert: &[u8], issuer: &[u8]) -> AppResult<bool> {
        let iss = self.cert_ctx(issuer)?;
        let mut blob = CRYPT_DATA_BLOB { cbData: cert.len() as DWORD, pbData: cert.as_ptr() as *mut u8 };
        let ok = unsafe {
            (self.api.CryptVerifyCertificateSignatureEx)(
                0, X509_ASN_ENCODING,
                CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB, &mut blob as *mut _ as *mut c_void,
                CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, iss.p as *mut c_void,
                0, null_mut(),
            )
        };
        Ok(ok != 0)
    }

    fn verify_detached(&self, cms: &[u8], content: &[u8]) -> AppResult<bool> {
        let para = CRYPT_VERIFY_MESSAGE_PARA {
            cbSize: std::mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as DWORD,
            dwMsgAndCertEncodingType: ENC,
            hCryptProv: 0,
            pfnGetSignerCertificate: null(),
            pvGetArg: null_mut(),
        };
        let ptrs = [content.as_ptr()];
        let lens = [content.len() as DWORD];
        let mut signer: PCCERT_CONTEXT = null();
        let ok = unsafe {
            (self.api.CryptVerifyDetachedMessageSignature)(&para, 0, cms.as_ptr(), cms.len() as DWORD, 1, ptrs.as_ptr(), lens.as_ptr(), &mut signer)
        };
        if !signer.is_null() {
            unsafe { (self.api.CertFreeCertificateContext)(signer) };
        }
        Ok(ok != 0)
    }

    fn encrypt(&self, data: &[u8], recipients: &[Vec<u8>], cipher: &str) -> AppResult<Vec<u8>> {
        let ctxs = recipients.iter().map(|d| self.cert_ctx(d)).collect::<AppResult<Vec<_>>>()?;
        let ptrs: Vec<PCCERT_CONTEXT> = ctxs.iter().map(|c| c.p).collect();
        let oid = match cipher {
            "kuznyechik" => CString::new("1.2.643.7.1.1.5.2.2").unwrap(),
            "magma" => CString::new("1.2.643.7.1.1.5.1.2").unwrap(),
            "gost89" => CString::new("1.2.643.2.2.21").unwrap(),
            "" | "default" => self.encrypt_oid.clone(),
            _ => return Err(AppError::new("bad_request", "cipher: kuznyechik | magma | gost89")),
        };
        let para = CRYPT_ENCRYPT_MESSAGE_PARA {
            cbSize: std::mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as DWORD,
            dwMsgEncodingType: ENC,
            hCryptProv: 0,
            ContentEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER { pszObjId: oid.as_ptr(), Parameters: CRYPT_DATA_BLOB { cbData: 0, pbData: null_mut() } },
            pvEncryptionAuxInfo: null_mut(),
            dwFlags: 0,
            dwInnerContentType: 0,
        };
        let mut n: DWORD = 0;
        let f = self.api.CryptEncryptMessage;
        if unsafe { f(&para, ptrs.len() as DWORD, ptrs.as_ptr(), data.as_ptr(), data.len() as DWORD, null_mut(), &mut n) } == 0 {
            return Err(self.api.err("crypto_error", "CryptEncryptMessage"));
        }
        let mut out = vec![0u8; n as usize];
        if unsafe { f(&para, ptrs.len() as DWORD, ptrs.as_ptr(), data.as_ptr(), data.len() as DWORD, out.as_mut_ptr(), &mut n) } == 0 {
            return Err(self.api.err("crypto_error", "CryptEncryptMessage"));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

/// Ключ во временном контейнере КриптоПро.
struct CpKey {
    api: Arc<Api>,
    store: HCERTSTORE,
    cert: PCCERT_CONTEXT,
    prov: HCRYPTPROV,
    free_prov: bool,
    key_spec: DWORD,
    prov_type: DWORD,
    hash_alg: DWORD,
    container: String,
    wchar: usize,
    lock: Mutex<()>,
}
unsafe impl Send for CpKey {}
unsafe impl Sync for CpKey {}

impl CpKey {
    fn new(cp: &CryptoPro, store: HCERTSTORE, cert: PCCERT_CONTEXT, pin: &str) -> AppResult<Self> {
        let api = cp.api.clone();
        // имя временного контейнера — чтобы удалить его при вытеснении
        let mut n: DWORD = 0;
        let mut container = String::new();
        let mut prov_type = PROV_GOST_2012_256;
        unsafe {
            if (api.CertGetCertificateContextProperty)(cert, CERT_KEY_PROV_INFO_PROP_ID, null_mut(), &mut n) != 0 {
                let mut buf = vec![0u8; n as usize];
                if (api.CertGetCertificateContextProperty)(cert, CERT_KEY_PROV_INFO_PROP_ID, buf.as_mut_ptr() as *mut c_void, &mut n) != 0 {
                    let info = &*(buf.as_ptr() as *const CRYPT_KEY_PROV_INFO);
                    container = cp.from_wide(info.pwszContainerName);
                    prov_type = info.dwProvType;
                }
            }
        }
        let mut prov: HCRYPTPROV = 0;
        let mut spec: DWORD = 0;
        let mut free: BOOL = 0;
        if unsafe { (api.CryptAcquireCertificatePrivateKey)(cert, CRYPT_ACQUIRE_SILENT_FLAG, null_mut(), &mut prov, &mut spec, &mut free) } == 0 {
            let e = api.err("invalid_container", "CryptAcquireCertificatePrivateKey");
            unsafe {
                (api.CertFreeCertificateContext)(cert);
                (api.CertCloseStore)(store, 0);
            }
            return Err(e);
        }
        // Если контейнер после импорта защищён паролем — вводим его в контекст.
        let cpin = Zeroizing::new(CString::new(pin).unwrap_or_default().into_bytes_with_nul());
        let pin_param = if spec == AT_SIGNATURE { PP_SIGNATURE_PIN } else { PP_KEYEXCHANGE_PIN };
        unsafe { (api.CryptSetProvParam)(prov, pin_param, cpin.as_ptr(), 0) };
        let hash_alg = if prov_type == PROV_GOST_2012_512 { CALG_GR3411_2012_512 } else { CALG_GR3411_2012_256 };
        Ok(Self { api, store, cert, prov, free_prov: free != 0, key_spec: spec, prov_type, hash_alg, container, wchar: cp.wchar, lock: Mutex::new(()) })
    }
}

impl KeyHandle for CpKey {
    fn sign_digest(&self, digest: &[u8]) -> AppResult<Vec<u8>> {
        let _g = self.lock.lock().unwrap();
        let api = &self.api;
        let mut h: HCRYPTHASH = 0;
        unsafe {
            if (api.CryptCreateHash)(self.prov, self.hash_alg, 0, 0, &mut h) == 0 {
                return Err(api.err("crypto_error", "CryptCreateHash"));
            }
            let res = (|| {
                if (api.CryptSetHashParam)(h, HP_HASHVAL, digest.as_ptr(), 0) == 0 {
                    return Err(api.err("crypto_error", "CryptSetHashParam(HP_HASHVAL)"));
                }
                let mut n: DWORD = 0;
                if (api.CryptSignHashA)(h, self.key_spec, null(), 0, null_mut(), &mut n) == 0 {
                    return Err(api.err("crypto_error", "CryptSignHash"));
                }
                let mut sig = vec![0u8; n as usize];
                if (api.CryptSignHashA)(h, self.key_spec, null(), 0, sig.as_mut_ptr(), &mut n) == 0 {
                    return Err(api.err("crypto_error", "CryptSignHash"));
                }
                sig.truncate(n as usize);
                Ok(sig)
            })();
            (api.CryptDestroyHash)(h);
            res
        }
    }

    fn decrypt(&self, cms: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        let _g = self.lock.lock().unwrap();
        let api = &self.api;
        unsafe {
            let msg = (api.CryptMsgOpenToDecode)(ENC, 0, 0, 0, null_mut(), null_mut());
            if msg.is_null() {
                return Err(api.err("crypto_error", "CryptMsgOpenToDecode"));
            }
            let res = (|| {
                if (api.CryptMsgUpdate)(msg, cms.as_ptr(), cms.len() as DWORD, 1) == 0 {
                    return Err(AppError::new("decrypt_failed", "Данные не являются CMS EnvelopedData"));
                }
                let mut count: DWORD = 0;
                let mut n = 4 as DWORD;
                (api.CryptMsgGetParam)(msg, CMSG_RECIPIENT_COUNT_PARAM, 0, &mut count as *mut _ as *mut c_void, &mut n);
                for idx in 0..count.max(1) {
                    let para = CMSG_CTRL_DECRYPT_PARA {
                        cbSize: std::mem::size_of::<CMSG_CTRL_DECRYPT_PARA>() as DWORD,
                        hCryptProv: self.prov,
                        dwKeySpec: self.key_spec,
                        dwRecipientIndex: idx,
                    };
                    if (api.CryptMsgControl)(msg, 0, CMSG_CTRL_DECRYPT, &para as *const _ as *const c_void) != 0 {
                        let mut len: DWORD = 0;
                        (api.CryptMsgGetParam)(msg, CMSG_CONTENT_PARAM, 0, null_mut(), &mut len);
                        let mut out = Zeroizing::new(vec![0u8; len as usize]);
                        if (api.CryptMsgGetParam)(msg, CMSG_CONTENT_PARAM, 0, out.as_mut_ptr() as *mut c_void, &mut len) == 0 {
                            return Err(api.err("decrypt_failed", "CryptMsgGetParam(CONTENT)"));
                        }
                        out.truncate(len as usize);
                        return Ok(out);
                    }
                }
                Err(AppError::new("decrypt_failed", "Данные зашифрованы не на этот ключ"))
            })();
            (api.CryptMsgClose)(msg);
            res
        }
    }

    fn export_pfx(&self, pin: &str) -> AppResult<Vec<u8>> {
        let _g = self.lock.lock().unwrap();
        let api = &self.api;
        let wpin = {
            let mut out = Zeroizing::new(Vec::new());
            if self.wchar == 2 {
                for u in pin.encode_utf16().chain(std::iter::once(0)) { out.extend_from_slice(&u.to_ne_bytes()); }
            } else {
                for c in pin.chars().chain(std::iter::once('\0')) { out.extend_from_slice(&(c as u32).to_ne_bytes()); }
            }
            out
        };
        unsafe {
            // Отдельное хранилище только с нашим сертификатом (+ привязка к ключу)
            let mem = (api.CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, null());
            if mem.is_null() {
                return Err(api.err("crypto_error", "CertOpenStore"));
            }
            let res = (|| {
                if (api.CertAddCertificateContextToStore)(mem, self.cert, CERT_STORE_ADD_ALWAYS, null_mut()) == 0 {
                    return Err(api.err("crypto_error", "CertAddCertificateContextToStore"));
                }
                let flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | REPORT_NO_PRIVATE_KEY;
                let mut blob = CRYPT_DATA_BLOB { cbData: 0, pbData: null_mut() };
                if (api.PFXExportCertStoreEx)(mem, &mut blob, wpin.as_ptr() as *const c_void, null_mut(), flags) == 0 {
                    return Err(api.err("crypto_error", "PFXExportCertStoreEx (ключ должен быть экспортируемым)"));
                }
                let mut out = vec![0u8; blob.cbData as usize];
                blob.pbData = out.as_mut_ptr();
                if (api.PFXExportCertStoreEx)(mem, &mut blob, wpin.as_ptr() as *const c_void, null_mut(), flags) == 0 {
                    return Err(api.err("crypto_error", "PFXExportCertStoreEx"));
                }
                out.truncate(blob.cbData as usize);
                Ok(out)
            })();
            (api.CertCloseStore)(mem, 0);
            res
        }
    }
}

impl Drop for CpKey {
    fn drop(&mut self) {
        let api = &self.api;
        unsafe {
            if self.free_prov && self.prov != 0 {
                (api.CryptReleaseContext)(self.prov, 0);
            }
            (api.CertFreeCertificateContext)(self.cert);
            (api.CertCloseStore)(self.store, 0);
            if !self.container.is_empty() {
                // удалить временный контейнер из HDIMAGE (tmpfs)
                if let Ok(name) = CString::new(self.container.clone()) {
                    let mut h: HCRYPTPROV = 0;
                    (api.CryptAcquireContextA)(&mut h, name.as_ptr(), null(), self.prov_type, CRYPT_DELETEKEYSET | CRYPT_SILENT);
                }
            }
        }
    }
}
