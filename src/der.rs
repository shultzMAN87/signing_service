//! Сборка CMS SignedData (CAdES-BES) в DER.
//!
//! Постоянные части (сертификат, издатель, signingCertificateV2) готовятся
//! один раз на ключ; на каждую подпись добавляются только время и хэш.
//! Подпись над signedAttrs делает провайдер (КриптоПро или OpenSSL).

pub fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let b = n.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
    let mut out = vec![0x80 | (b.len() - first) as u8];
    out.extend_from_slice(&b[first..]);
    out
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    out.extend(len(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|s| s.parse().expect("OID")).collect();
    let mut body = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        body.extend(tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    tlv(0x06, &body)
}

pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const OID_SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";

/// Шаблон подписи для одного сертификата.
pub struct CadesTemplate {
    cert_der: Vec<u8>,
    issuer_serial: Vec<u8>,
    digest_alg: Vec<u8>,
    sig_alg: Vec<u8>,
    attr_content_type: Vec<u8>,
    attr_signing_cert: Vec<u8>,
}

impl CadesTemplate {
    /// `cert_hash` — хэш сертификата тем же алгоритмом, что и документ.
    pub fn new(ci: &crate::cert::CertInfo, cert_hash: &[u8]) -> Self {
        let digest_alg = seq(&[&oid(ci.digest_oid)]);
        // ESSCertIDv2 { hashAlgorithm, certHash, issuerSerial { GeneralNames{[4] Name}, serial } }
        let issuer_serial_v2 = seq(&[&tlv(0x30, &tlv(0xA4, &ci.issuer_raw)), &ci.serial_raw]);
        let ess = seq(&[&digest_alg, &tlv(0x04, cert_hash), &issuer_serial_v2]);
        let signing_cert_v2 = seq(&[&seq(&[&ess])]);
        Self {
            cert_der: ci.der.clone(),
            issuer_serial: [ci.issuer_raw.as_slice(), ci.serial_raw.as_slice()].concat(),
            sig_alg: seq(&[&oid(ci.key_oid)]),
            attr_content_type: seq(&[&oid(OID_CONTENT_TYPE), &tlv(0x31, &oid(OID_DATA))]),
            attr_signing_cert: seq(&[&oid(OID_SIGNING_CERT_V2), &tlv(0x31, &signing_cert_v2)]),
            digest_alg,
        }
    }

    /// signedAttrs (содержимое SET) для данного хэша документа и времени.
    pub fn signed_attrs(&self, content_digest: &[u8], when: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        let t = when.format("%y%m%d%H%M%SZ").to_string();
        let mut attrs = vec![
            self.attr_content_type.clone(),
            seq(&[&oid(OID_SIGNING_TIME), &tlv(0x31, &tlv(0x17, t.as_bytes()))]),
            seq(&[&oid(OID_MESSAGE_DIGEST), &tlv(0x31, &tlv(0x04, content_digest))]),
            self.attr_signing_cert.clone(),
        ];
        attrs.sort(); // DER: элементы SET OF упорядочены по кодировке
        attrs.concat()
    }

    /// Что подписывается: signedAttrs с тегом SET (RFC 5652, 5.4).
    pub fn to_be_signed(attrs_body: &[u8]) -> Vec<u8> {
        tlv(0x31, attrs_body)
    }

    pub fn assemble(&self, attrs_body: &[u8], signature: &[u8], content: Option<&[u8]>) -> Vec<u8> {
        let int1 = [0x02u8, 0x01, 0x01];
        let signer = seq(&[
            &int1,
            &tlv(0x30, &self.issuer_serial),
            &self.digest_alg,
            &tlv(0xA0, attrs_body),
            &self.sig_alg,
            &tlv(0x04, signature),
        ]);
        let mut encap = oid(OID_DATA);
        if let Some(c) = content {
            encap.extend(tlv(0xA0, &tlv(0x04, c)));
        }
        let sd = seq(&[
            &int1,
            &tlv(0x31, &self.digest_alg),
            &tlv(0x30, &encap),
            &tlv(0xA0, &self.cert_der),
            &tlv(0x31, &signer),
        ]);
        seq(&[&oid(OID_SIGNED_DATA), &tlv(0xA0, &sd)])
    }
}

/// PEM-обёртка.
pub fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

/// DER из DER/PEM/Base64.
pub fn to_der(blob: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let s = trim(blob);
    if s.first() == Some(&0x30) {
        return Some(s.to_vec());
    }
    let text = std::str::from_utf8(s).ok()?;
    let body: String = if text.starts_with("-----") {
        text.lines().filter(|l| !l.starts_with("-----")).collect()
    } else {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    };
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    &b[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oid_encoding() {
        assert_eq!(oid("1.2.840.113549.1.7.2"), hex::decode("06092a864886f70d010702").unwrap());
        assert_eq!(oid("1.2.643.7.1.1.2.2"), hex::decode("06082a85030701010202").unwrap());
    }
    #[test]
    fn long_len() {
        assert_eq!(len(300), vec![0x82, 0x01, 0x2c]);
    }
}
