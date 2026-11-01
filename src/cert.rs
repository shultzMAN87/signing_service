//! Разбор сертификата ГОСТ (x509-parser, без криптографии).
use crate::error::{AppError, AppResult};
use chrono::{DateTime, TimeZone, Utc};
use sha1::{Digest, Sha1};
use x509_parser::prelude::*;

#[derive(Clone, Debug)]
pub struct CertInfo {
    pub der: Vec<u8>,
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_alg: &'static str,
    pub key_oid: &'static str,
    pub digest_oid: &'static str,
    pub digest_len: usize,
    /// Name издателя в DER (для IssuerAndSerialNumber)
    pub issuer_raw: Vec<u8>,
    /// INTEGER серийного номера в DER
    pub serial_raw: Vec<u8>,
}

pub const GOST256: &str = "1.2.643.7.1.1.1.1";
pub const GOST512: &str = "1.2.643.7.1.1.1.2";
pub const STREEBOG256: &str = "1.2.643.7.1.1.2.2";
pub const STREEBOG512: &str = "1.2.643.7.1.1.2.3";

pub fn thumbprint(der: &[u8]) -> String {
    hex::encode_upper(Sha1::digest(der))
}

pub fn parse(der: &[u8]) -> AppResult<CertInfo> {
    let (_, c) = X509Certificate::from_der(der).map_err(|_| AppError::new("invalid_container", "Не удалось разобрать сертификат"))?;
    let alg = c.tbs_certificate.subject_pki.algorithm.algorithm.to_id_string();
    let (key_alg, key_oid, digest_oid, digest_len) = match alg.as_str() {
        GOST256 => ("gost2012_256", GOST256, STREEBOG256, 32),
        GOST512 => ("gost2012_512", GOST512, STREEBOG512, 64),
        other => return Err(AppError::new("not_gost", format!("Алгоритм ключа {other} не ГОСТ Р 34.10-2012"))),
    };
    let ts = |t: &ASN1Time| Utc.timestamp_opt(t.timestamp(), 0).single().unwrap_or_default();
    let serial_bytes = c.tbs_certificate.raw_serial();
    Ok(CertInfo {
        der: der.to_vec(),
        thumbprint: thumbprint(der),
        subject: name(c.subject()),
        issuer: name(c.issuer()),
        serial: hex::encode_upper(serial_bytes),
        not_before: ts(&c.validity().not_before),
        not_after: ts(&c.validity().not_after),
        key_alg,
        key_oid,
        digest_oid,
        digest_len,
        issuer_raw: c.issuer().as_raw().to_vec(),
        serial_raw: crate::der::tlv(0x02, serial_bytes),
    })
}

fn name(n: &X509Name) -> String {
    let mut parts = Vec::new();
    for rdn in n.iter() {
        for a in rdn.iter() {
            let key = match a.attr_type().to_id_string().as_str() {
                "2.5.4.3" => "CN".to_string(),
                "2.5.4.10" => "O".to_string(),
                "2.5.4.11" => "OU".to_string(),
                "2.5.4.6" => "C".to_string(),
                "2.5.4.7" => "L".to_string(),
                "2.5.4.8" => "ST".to_string(),
                "2.5.4.9" => "STREET".to_string(),
                "2.5.4.4" => "SN".to_string(),
                "2.5.4.42" => "G".to_string(),
                "2.5.4.12" => "T".to_string(),
                "1.2.840.113549.1.9.1" => "E".to_string(),
                "1.2.643.100.1" => "OGRN".to_string(),
                "1.2.643.100.3" => "SNILS".to_string(),
                "1.2.643.3.131.1.1" => "INN".to_string(),
                "1.2.643.100.4" => "INNLE".to_string(),
                o => o.to_string(),
            };
            let val = a.as_str().map(String::from).unwrap_or_else(|_| hex::encode(a.attr_value().data));
            parts.push(format!("{key}={val}"));
        }
    }
    parts.join(", ")
}

/// Сертификаты из PEM-бандла.
pub fn load_pem_bundle(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE") {
            inside = true;
            cur.clear();
        } else if line.starts_with("-----END CERTIFICATE") {
            inside = false;
            if let Some(d) = crate::der::to_der(cur.as_bytes()) {
                out.push(d);
            }
        } else if inside {
            cur.push_str(line.trim());
        }
    }
    out
}

/// Проверка подписи сертификата и издателя по имени (без отзыва).
pub fn issued_by(cert: &[u8], issuer: &[u8]) -> bool {
    match (X509Certificate::from_der(cert), X509Certificate::from_der(issuer)) {
        (Ok((_, c)), Ok((_, i))) => c.issuer().as_raw() == i.subject().as_raw(),
        _ => false,
    }
}

