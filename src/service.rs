//! Бизнес-логика (ТЗ, разделы 2–3).
use crate::cert::{self, CertInfo};
use crate::config::Config;
use crate::crypto::{KeyHandle, Provider};
use crate::der::{self, CadesTemplate};
use crate::error::{AppError, AppResult};
use crate::kms::{self, Kms};
use crate::metrics::Metrics;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use moka::future::Cache;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::num::NonZeroU32;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Actor {
    pub id: String,
    pub roles: Vec<String>,
    pub request_id: String,
}
impl Actor {
    pub fn has(&self, r: &str) -> bool {
        self.roles.iter().any(|x| x == r)
    }
    fn require(&self, r: &str) -> AppResult<()> {
        if self.has(r) { Ok(()) } else { Err(AppError::new("forbidden", format!("Нужна роль {r}"))) }
    }
}

/// Открытый ключ в кэше. Drop последней ссылки освобождает ключ в провайдере.
pub struct KeyCtx {
    pub key: Box<dyn KeyHandle>,
    pub cert: CertInfo,
    pub tpl: CadesTemplate,
    /// Переворачивать ли подпись провайдера для CMS (определяется пробной подписью).
    pub reverse: bool,
}

pub struct App {
    pub cfg: Config,
    pub meta: PgPool,
    pub store: PgPool,
    pub kms: Arc<dyn Kms>,
    pub prov: Arc<dyn Provider>,
    pub cache: Cache<String, Arc<KeyCtx>>,
    pub metrics: Metrics,
    pub trust: Vec<Vec<u8>>,
    pub transport: Option<Arc<KeyCtx>>,
    rl_client: Option<DefaultKeyedRateLimiter<String>>,
    rl_key: Option<DefaultKeyedRateLimiter<String>>,
    /// Когда last_used_at ключа последний раз писался в БД (не чаще раза в минуту:
    /// иначе все подписи одним ключом выстраиваются в очередь за блокировкой строки).
    last_used: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientRight {
    pub id: String,
    #[serde(default = "yes")]
    pub sign: bool,
    #[serde(default)]
    pub decrypt: bool,
}
fn yes() -> bool {
    true
}

pub enum SignInput {
    Hash(Vec<u8>),
    Data(Vec<u8>),
}

pub struct Output {
    pub body: Vec<u8>,
    pub content_type: &'static str,
    pub filename: String,
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| AppError::new("crypto_error", e.to_string()))?
}

fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn new_pin() -> Zeroizing<String> {
    let mut b = [0u8; 24]; // 192 бита
    rand::rng().fill_bytes(&mut b);
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

impl App {
    pub async fn new(cfg: Config) -> AppResult<Arc<Self>> {
        let meta = PgPoolOptions::new().max_connections(32).connect(&cfg.meta_dsn).await?;
        let store = PgPoolOptions::new().max_connections(32).connect(&cfg.store_dsn).await?;
        sqlx::raw_sql(include_str!("../sql/meta.sql")).execute(&meta).await?;
        sqlx::raw_sql(include_str!("../sql/containers.sql")).execute(&store).await?;
        let kms = kms::make(&cfg)?;
        for k in [&cfg.kek_container, &cfg.kek_pin] {
            kms.ensure_key(k).await?;
            kms.self_check(k).await.map_err(|e| AppError::new(e.code, format!("Самопроверка KMS, ключ {k}: {}", e.message)))?;
        }
        tracing::info!("KMS: самопроверка ключей пройдена");
        let prov = crate::crypto::make(&cfg)?;
        let trust = if cfg.trust_ca.is_empty() {
            tracing::warn!("ESIGN_TRUST_CA не задан — цепочка сертификатов не проверяется (только для стенда)");
            vec![]
        } else {
            let text = std::fs::read_to_string(&cfg.trust_ca).map_err(|e| AppError::new("crypto_error", format!("ESIGN_TRUST_CA: {e}")))?;
            cert::load_pem_bundle(&text)
        };
        let cache = Cache::builder()
            .max_capacity(cfg.cache_max)
            .time_to_idle(std::time::Duration::from_secs(cfg.cache_idle_sec))
            .time_to_live(std::time::Duration::from_secs(cfg.cache_ttl_sec))
            .build();
        let rl = |n: u32| NonZeroU32::new(n).map(|n| RateLimiter::keyed(Quota::per_second(n)));
        let mut app = Self {
            rl_client: rl(cfg.rate_per_client),
            rl_key: rl(cfg.rate_per_key),
            cfg,
            meta,
            store,
            kms,
            prov,
            cache,
            metrics: Metrics::new(),
            trust,
            transport: None,
            last_used: Default::default(),
        };
        if !app.cfg.transport_pfx.is_empty() {
            let pfx = std::fs::read(&app.cfg.transport_pfx).map_err(|e| AppError::new("crypto_error", format!("ESIGN_TRANSPORT_PFX: {e}")))?;
            let pin = Zeroizing::new(app.cfg.transport_pin.clone());
            app.transport = Some(app.open_ctx(pfx, pin).await?);
            tracing::info!("транспортный ключ загружен: PIN можно передавать в pin_envelope");
        }
        tracing::info!(provider = app.prov.name(), kms = %app.cfg.kms, "сервис готов");
        Ok(Arc::new(app))
    }

    // ------------------------------------------------------------ аудит
    pub async fn audit(&self, actor: Option<&Actor>, op: &str, result: &str, tp: Option<&str>, doc_hash: Option<&[u8]>, error: Option<&str>, details: Value) {
        let r = sqlx::query("INSERT INTO audit(request_id, actor, op, thumbprint, doc_hash, details, result, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(actor.map(|a| a.request_id.clone()))
            .bind(actor.map(|a| a.id.clone()).unwrap_or_else(|| "system".into()))
            .bind(op)
            .bind(tp)
            .bind(doc_hash.map(hex::encode))
            .bind(sqlx::types::Json(details))
            .bind(result)
            .bind(error)
            .execute(&self.meta)
            .await;
        if let Err(e) = r {
            tracing::error!(error = %e, "audit write failed");
        }
    }

    fn rate(&self, actor: &Actor, tp: &str) -> AppResult<()> {
        if let Some(l) = &self.rl_client {
            if l.check_key(&actor.id).is_err() {
                return Err(AppError::new("rate_limited", "Превышен лимит запросов системы"));
            }
        }
        if let Some(l) = &self.rl_key {
            if l.check_key(&tp.to_string()).is_err() {
                return Err(AppError::new("rate_limited", "Превышен лимит запросов по ключу"));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ открытие ключа
    /// Подпись хэша шаблоном CAdES-BES.
    fn cms_sign(prov: &dyn Provider, key: &dyn KeyHandle, ci: &CertInfo, tpl: &CadesTemplate, reverse: bool, content_digest: &[u8], content: Option<&[u8]>) -> AppResult<Vec<u8>> {
        let attrs = tpl.signed_attrs(content_digest, now());
        let h = prov.digest(ci.digest_oid, &CadesTemplate::to_be_signed(&attrs))?;
        let mut sig = key.sign_digest(&h)?;
        if reverse {
            sig.reverse();
        }
        Ok(tpl.assemble(&attrs, &sig, content))
    }

    /// Открыть PFX и проверить ключ пробной подписью (заодно определить порядок байт).
    async fn open_ctx(&self, pfx: Vec<u8>, pin: Zeroizing<String>) -> AppResult<Arc<KeyCtx>> {
        let prov = self.prov.clone();
        let (ctx, _) = blocking(move || Self::open_blocking(&*prov, &pfx, &pin)).await?;
        Ok(Arc::new(ctx))
    }

    fn open_blocking(prov: &dyn Provider, pfx: &[u8], pin: &str) -> AppResult<(KeyCtx, Vec<Vec<u8>>)> {
        let opened = prov.open_pfx(pfx, pin)?;
        let ci = cert::parse(&opened.cert_der)?;
        let tpl = CadesTemplate::new(&ci, &prov.digest(ci.digest_oid, &ci.der)?);
        let mut probe = b"esign key probe ".to_vec();
        probe.extend(Uuid::new_v4().as_bytes());
        let d = prov.digest(ci.digest_oid, &probe)?;
        let mut reverse = None;
        for rev in [false, true] {
            let cms = Self::cms_sign(prov, &*opened.key, &ci, &tpl, rev, &d, None)?;
            if prov.verify_detached(&cms, &probe)? {
                reverse = Some(rev);
                break;
            }
        }
        let reverse = reverse.ok_or_else(|| AppError::new("key_mismatch", "Пробная подпись не проверяется сертификатом"))?;
        Ok((KeyCtx { key: opened.key, cert: ci, tpl, reverse }, opened.chain))
    }

    fn verify_chain(prov: &dyn Provider, trust: &[Vec<u8>], cert_der: &[u8], chain: &[Vec<u8>]) -> AppResult<()> {
        if trust.is_empty() {
            return Ok(());
        }
        let untrusted = AppError::new("untrusted_chain", "Цепочка сертификата не строится до доверенного УЦ");
        let mut cur = cert_der.to_vec();
        for _ in 0..8 {
            if trust.iter().any(|t| t == &cur) {
                return Ok(());
            }
            let issuer = trust.iter().chain(chain.iter()).find(|c| cert::issued_by(&cur, c) && *c != &cur).cloned();
            let Some(issuer) = issuer else { return Err(untrusted) };
            if !prov.verify_cert_signature(&cur, &issuer)? {
                return Err(untrusted);
            }
            if trust.iter().any(|t| t == &issuer) {
                return Ok(());
            }
            cur = issuer;
        }
        Err(untrusted)
    }

    async fn load_ctx(&self, tp: &str) -> AppResult<Arc<KeyCtx>> {
        let row = sqlx::query("SELECT ciphertext, dek_wrapped FROM containers WHERE thumbprint=$1").bind(tp).fetch_optional(&self.store).await?;
        let pin_row = sqlx::query("SELECT pin_ct FROM keys WHERE thumbprint=$1").bind(tp).fetch_optional(&self.meta).await?;
        let (Some(row), Some(pin_row)) = (row, pin_row) else { return Err(AppError::code("key_not_found")) };
        let pin_ct: Option<String> = pin_row.get("pin_ct");
        let pin_ct = pin_ct.ok_or_else(|| AppError::code("key_not_found"))?;
        let ct: Vec<u8> = row.get("ciphertext");
        let wrapped: String = row.get("dek_wrapped");
        let pfx = kms::unseal(&*self.kms, &self.cfg.kek_container, &ct, &wrapped, tp).await?;
        let pin_raw = self.kms.decrypt(&self.cfg.kek_pin, &pin_ct, tp).await?;
        let pin = Zeroizing::new(String::from_utf8(pin_raw.to_vec()).map_err(|_| AppError::code("crypto_error"))?);
        self.metrics.cache_misses.inc();
        self.open_ctx(pfx.to_vec(), pin).await
    }

    async fn ctx(&self, tp: &str) -> AppResult<Arc<KeyCtx>> {
        if let Some(c) = self.cache.get(tp).await {
            self.metrics.cache_hits.inc();
            return Ok(c);
        }
        let r = self.cache.try_get_with(tp.to_string(), self.load_ctx(tp)).await.map_err(|e| (*e).clone());
        self.metrics.cache_entries.set(self.cache.entry_count() as i64);
        r
    }

    pub async fn invalidate(&self, tp: Option<&str>) {
        match tp {
            Some(t) => self.cache.invalidate(t).await,
            None => self.cache.invalidate_all(),
        }
        self.cache.run_pending_tasks().await;
        self.metrics.cache_entries.set(self.cache.entry_count() as i64);
    }

    // ------------------------------------------------------------ Ф-1 загрузка
    pub async fn upload_container(&self, a: &Actor, blob: Vec<u8>, key_type: &str, owner: Option<String>, clients: Vec<ClientRight>) -> AppResult<Value> {
        a.require("admin")?;
        if key_type != "organization" && key_type != "employee" {
            return Err(AppError::new("bad_request", "key_type: organization | employee"));
        }
        if key_type == "employee" && owner.as_deref().unwrap_or("").is_empty() {
            return Err(AppError::new("bad_request", "Для КЭП сотрудника нужен owner_login"));
        }
        if blob.len() > self.cfg.max_container {
            return Err(AppError::code("too_large"));
        }
        match blob.first() {
            Some(0x30) => {}
            Some(b'P') if blob.starts_with(b"PK") => {
                return Err(AppError::new("unsupported_format", "Папка контейнера КриптоПро не принимается: экспортируйте ключ в PFX"))
            }
            _ => return Err(AppError::new("unsupported_format", "Ожидается PFX (PKCS#12)")),
        }
        let id = Uuid::new_v4();
        let ctx = format!("upload:{id}");
        let (ct, wrapped) = kms::seal(&*self.kms, &self.cfg.kek_container, &blob, &ctx).await?;
        let expires = now() + Duration::minutes(self.cfg.upload_ttl_min);
        sqlx::query("INSERT INTO staged(upload_id, ciphertext, dek_wrapped) VALUES ($1,$2,$3)").bind(id).bind(ct).bind(wrapped).execute(&self.store).await?;
        sqlx::query("INSERT INTO uploads(upload_id, created_by, key_type, owner_login, clients, expires_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(id).bind(&a.id).bind(key_type).bind(&owner).bind(sqlx::types::Json(&clients)).bind(expires)
            .execute(&self.meta).await?;
        self.audit(Some(a), "upload.container", "ok", None, None, None, json!({"upload": id, "size": blob.len()})).await;
        Ok(json!({"upload_id": id, "expires_at": expires}))
    }

    async fn drop_upload(&self, id: Uuid, status: &str) {
        let _ = sqlx::query("DELETE FROM staged WHERE upload_id=$1").bind(id).execute(&self.store).await;
        let _ = sqlx::query("UPDATE uploads SET status=$1 WHERE upload_id=$2").bind(status).bind(id).execute(&self.meta).await;
    }

    pub async fn upload_pin(&self, a: &Actor, id: Uuid, pin: Option<Zeroizing<String>>, envelope: Option<String>) -> AppResult<Value> {
        let t0 = std::time::Instant::now();
        let up = sqlx::query("SELECT * FROM uploads WHERE upload_id=$1").bind(id).fetch_optional(&self.meta).await?;
        let Some(up) = up else { return Err(AppError::code("upload_not_found")) };
        let status: String = up.get("status");
        if status != "pending" {
            return Err(AppError::code("upload_not_found"));
        }
        let owner: Option<String> = up.get("owner_login");
        if !(a.has("admin") || owner.as_deref() == Some(a.id.as_str())) {
            return Err(AppError::new("forbidden", "PIN передаёт администратор или владелец КЭП"));
        }
        let expires: DateTime<Utc> = up.get("expires_at");
        if expires < now() {
            self.drop_upload(id, "expired").await;
            return Err(AppError::code("upload_expired"));
        }
        let pin: Zeroizing<String> = if let Some(env) = envelope {
            let t = self.transport.clone().ok_or_else(|| AppError::new("bad_request", "Транспортный ключ не настроен (ESIGN_TRANSPORT_PFX)"))?;
            let der = der::to_der(env.as_bytes()).ok_or_else(|| AppError::new("bad_request", "pin_envelope: ожидается CMS"))?;
            let raw = blocking(move || t.key.decrypt(&der)).await.map_err(|_| AppError::new("bad_request", "pin_envelope не расшифровывается транспортным ключом"))?;
            Zeroizing::new(String::from_utf8(raw.to_vec()).map_err(|_| AppError::new("bad_request", "PIN не UTF-8"))?)
        } else if let Some(p) = pin {
            if !self.cfg.test_mode {
                return Err(AppError::new("bad_request", "Открытый PIN запрещён: используйте pin_envelope"));
            }
            p
        } else {
            return Err(AppError::new("bad_request", "Нужен pin_envelope"));
        };

        let staged = sqlx::query("SELECT ciphertext, dek_wrapped FROM staged WHERE upload_id=$1").bind(id).fetch_optional(&self.store).await?;
        let Some(staged) = staged else { return Err(AppError::code("upload_not_found")) };
        let pfx = kms::unseal(&*self.kms, &self.cfg.kek_container, &staged.get::<Vec<u8>, _>("ciphertext"), &staged.get::<String, _>("dek_wrapped"), &format!("upload:{id}")).await?;

        // Открыть, проверить, пересохранить под PIN сервиса — всё в одном блокирующем вызове.
        let prov = self.prov.clone();
        let trust = self.trust.clone();
        let service_pin = new_pin();
        let sp = service_pin.clone();
        let res = blocking(move || {
            let (ctx, chain) = Self::open_blocking(&*prov, &pfx, &pin)?;
            let ci = ctx.cert.clone();
            if ci.not_after < now() {
                return Err(AppError::new("cert_expired", "Срок действия сертификата истёк"));
            }
            if ci.not_before > now() {
                return Err(AppError::new("cert_not_yet_valid", "Сертификат ещё не начал действовать"));
            }
            Self::verify_chain(&*prov, &trust, &ci.der, &chain)?;
            let new_pfx = ctx.key.export_pfx(&sp)?;
            Ok((ci, new_pfx))
        })
        .await;
        let (ci, new_pfx) = match res {
            Ok(v) => v,
            Err(e) if e.code == "invalid_pin" => {
                let attempts: i32 = up.get("attempts");
                sqlx::query("UPDATE uploads SET attempts=attempts+1 WHERE upload_id=$1").bind(id).execute(&self.meta).await?;
                let left = self.cfg.pin_attempts - attempts - 1;
                self.audit(Some(a), "upload.pin", "error", None, None, Some("invalid_pin"), json!({"upload": id, "attempts_left": left})).await;
                if left <= 0 {
                    self.drop_upload(id, "failed").await;
                    return Err(AppError::new("upload_expired", "Исчерпаны попытки ввода PIN, заявка аннулирована"));
                }
                return Err(AppError::new("invalid_pin", format!("Неверный PIN, осталось попыток: {left}")));
            }
            Err(e) => {
                self.drop_upload(id, "failed").await;
                self.audit(Some(a), "upload.pin", "error", None, None, Some(e.code), json!({"upload": id})).await;
                return Err(e);
            }
        };
        let tp = ci.thumbprint.clone();
        let exists = sqlx::query("SELECT 1 FROM keys WHERE thumbprint=$1 AND status<>'purged'").bind(&tp).fetch_optional(&self.meta).await?;
        if exists.is_some() {
            self.drop_upload(id, "failed").await;
            return Err(AppError::new("key_exists", format!("Ключ {tp} уже загружен")));
        }
        let (ct, wrapped) = kms::seal(&*self.kms, &self.cfg.kek_container, &new_pfx, &tp).await?;
        let pin_ct = self.kms.encrypt(&self.cfg.kek_pin, service_pin.as_bytes(), &tp).await?;
        sqlx::query("INSERT INTO containers(thumbprint, ciphertext, dek_wrapped, fmt) VALUES ($1,$2,$3,'pfx') ON CONFLICT (thumbprint) DO UPDATE SET ciphertext=EXCLUDED.ciphertext, dek_wrapped=EXCLUDED.dek_wrapped, updated_at=now()")
            .bind(&tp).bind(ct).bind(wrapped).execute(&self.store).await?;
        let clients: sqlx::types::Json<Vec<ClientRight>> = up.get("clients");
        let key_type: String = up.get("key_type");
        let tx_res: Result<(), sqlx::Error> = async {
            let mut tx = self.meta.begin().await?;
            sqlx::query("DELETE FROM keys WHERE thumbprint=$1 AND status='purged'").bind(&tp).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO keys(thumbprint, key_type, owner_login, subject, issuer, serial, not_before, not_after, key_alg, cert_der, status, pin_ct, pin_changed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',$11,now())")
                .bind(&tp).bind(&key_type).bind(&owner).bind(&ci.subject).bind(&ci.issuer).bind(&ci.serial)
                .bind(ci.not_before).bind(ci.not_after).bind(ci.key_alg).bind(&ci.der).bind(&pin_ct)
                .execute(&mut *tx).await?;
            for c in clients.0.iter() {
                sqlx::query("INSERT INTO key_clients(thumbprint, client_id, can_sign, can_decrypt) VALUES ($1,$2,$3,$4)")
                    .bind(&tp).bind(&c.id).bind(c.sign).bind(c.decrypt).execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE uploads SET status='done', thumbprint=$1 WHERE upload_id=$2").bind(&tp).bind(id).execute(&mut *tx).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = tx_res {
            let _ = sqlx::query("DELETE FROM containers WHERE thumbprint=$1").bind(&tp).execute(&self.store).await;
            return Err(e.into());
        }
        let _ = sqlx::query("DELETE FROM staged WHERE upload_id=$1").bind(id).execute(&self.store).await;
        self.audit(Some(a), "key.install", "ok", Some(&tp), None, None, json!({"upload": id, "pin_replaced": true, "provider": self.prov.name()})).await;
        self.metrics.op_seconds.with_label_values(&["install"]).observe(t0.elapsed().as_secs_f64());
        self.key_card(&tp).await
    }

    // ------------------------------------------------------------ просмотр
    async fn key_row(&self, tp: &str) -> AppResult<sqlx::postgres::PgRow> {
        let r = sqlx::query("SELECT * FROM keys WHERE thumbprint=$1").bind(tp.to_uppercase()).fetch_optional(&self.meta).await?;
        match r {
            Some(r) if r.get::<String, _>("status") != "purged" => Ok(r),
            _ => Err(AppError::code("key_not_found")),
        }
    }

    pub async fn key_card(&self, tp: &str) -> AppResult<Value> {
        let r = self.key_row(tp).await?;
        let tp: String = r.get("thumbprint");
        let clients = sqlx::query("SELECT client_id, can_sign, can_decrypt FROM key_clients WHERE thumbprint=$1 ORDER BY client_id").bind(&tp).fetch_all(&self.meta).await?;
        let clients: Vec<Value> = clients.iter().map(|c| json!({"id": c.get::<String,_>("client_id"), "sign": c.get::<bool,_>("can_sign"), "decrypt": c.get::<bool,_>("can_decrypt")})).collect();
        Ok(json!({
            "thumbprint": tp,
            "key_type": r.get::<String,_>("key_type"),
            "owner_login": r.get::<Option<String>,_>("owner_login"),
            "subject": r.get::<String,_>("subject"),
            "issuer": r.get::<String,_>("issuer"),
            "serial": r.get::<String,_>("serial"),
            "key_alg": r.get::<String,_>("key_alg"),
            "not_before": r.get::<DateTime<Utc>,_>("not_before"),
            "not_after": r.get::<DateTime<Utc>,_>("not_after"),
            "status": r.get::<String,_>("status"),
            "clients": clients,
            "pin_changed_at": r.get::<Option<DateTime<Utc>>,_>("pin_changed_at"),
            "last_used_at": r.get::<Option<DateTime<Utc>>,_>("last_used_at"),
            "purge_after": r.get::<Option<DateTime<Utc>>,_>("purge_after"),
        }))
    }

    pub async fn list_keys(&self, a: &Actor) -> AppResult<Value> {
        let rows = if a.has("admin") || a.has("auditor") {
            sqlx::query("SELECT thumbprint FROM keys WHERE status<>'purged' ORDER BY subject").fetch_all(&self.meta).await?
        } else {
            sqlx::query("SELECT k.thumbprint FROM keys k JOIN key_clients c USING (thumbprint) WHERE c.client_id=$1 AND k.status<>'purged' ORDER BY k.subject").bind(&a.id).fetch_all(&self.meta).await?
        };
        let mut out = Vec::new();
        for r in rows {
            out.push(self.key_card(&r.get::<String, _>("thumbprint")).await?);
        }
        Ok(Value::Array(out))
    }

    pub async fn get_key(&self, a: &Actor, tp: &str) -> AppResult<Value> {
        let card = self.key_card(tp).await?;
        let allowed = a.has("admin") || a.has("auditor") || card["clients"].as_array().unwrap().iter().any(|c| c["id"] == a.id.as_str());
        if !allowed {
            return Err(AppError::code("key_not_found"));
        }
        Ok(card)
    }

    pub async fn certificate(&self, a: &Actor, tp: &str) -> AppResult<Vec<u8>> {
        self.get_key(a, tp).await?;
        Ok(self.key_row(tp).await?.get("cert_der"))
    }

    // ------------------------------------------------------------ Ф-4 управление
    pub async fn set_status(&self, a: &Actor, tp: &str, status: &str) -> AppResult<Value> {
        a.require("admin")?;
        let r = self.key_row(tp).await?;
        let tp: String = r.get("thumbprint");
        if r.get::<String, _>("status") == "deleted" {
            return Err(AppError::new("key_deleted", "Удалённый ключ восстанавливается через restore"));
        }
        sqlx::query("UPDATE keys SET status=$1, updated_at=now() WHERE thumbprint=$2").bind(status).bind(&tp).execute(&self.meta).await?;
        self.invalidate(Some(&tp)).await;
        self.audit(Some(a), if status == "blocked" { "key.block" } else { "key.unblock" }, "ok", Some(&tp), None, None, json!({})).await;
        self.key_card(&tp).await
    }

    pub async fn set_clients(&self, a: &Actor, tp: &str, clients: Vec<ClientRight>) -> AppResult<Value> {
        a.require("admin")?;
        let tp: String = self.key_row(tp).await?.get("thumbprint");
        let mut tx = self.meta.begin().await?;
        sqlx::query("DELETE FROM key_clients WHERE thumbprint=$1").bind(&tp).execute(&mut *tx).await?;
        for c in &clients {
            sqlx::query("INSERT INTO key_clients(thumbprint, client_id, can_sign, can_decrypt) VALUES ($1,$2,$3,$4)").bind(&tp).bind(&c.id).bind(c.sign).bind(c.decrypt).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        self.audit(Some(a), "key.clients", "ok", Some(&tp), None, None, json!({"clients": clients})).await;
        self.key_card(&tp).await
    }

    pub async fn rotate_pin(&self, a: &Actor, tp: &str) -> AppResult<Value> {
        a.require("admin")?;
        let r = self.key_row(tp).await?;
        let tp: String = r.get("thumbprint");
        let ctx = self.load_ctx(&tp).await?;
        let pin = new_pin();
        let p2 = pin.clone();
        let new_pfx = blocking(move || ctx.key.export_pfx(&p2)).await?;
        let (ct, wrapped) = kms::seal(&*self.kms, &self.cfg.kek_container, &new_pfx, &tp).await?;
        let pin_ct = self.kms.encrypt(&self.cfg.kek_pin, pin.as_bytes(), &tp).await?;
        sqlx::query("UPDATE containers SET ciphertext=$1, dek_wrapped=$2, updated_at=now() WHERE thumbprint=$3").bind(ct).bind(wrapped).bind(&tp).execute(&self.store).await?;
        sqlx::query("UPDATE keys SET pin_ct=$1, pin_changed_at=now(), updated_at=now() WHERE thumbprint=$2").bind(pin_ct).bind(&tp).execute(&self.meta).await?;
        self.invalidate(Some(&tp)).await;
        self.audit(Some(a), "key.pin_rotate", "ok", Some(&tp), None, None, json!({})).await;
        self.key_card(&tp).await
    }

    // ------------------------------------------------------------ Ф-3 удаление
    pub async fn delete_key(&self, a: &Actor, tp: &str) -> AppResult<Value> {
        a.require("admin")?;
        let tp: String = self.key_row(tp).await?.get("thumbprint");
        let purge_after = now() + Duration::days(self.cfg.retention_days);
        sqlx::query("UPDATE keys SET status='deleted', deleted_at=now(), purge_after=$1, updated_at=now() WHERE thumbprint=$2").bind(purge_after).bind(&tp).execute(&self.meta).await?;
        self.invalidate(Some(&tp)).await;
        self.audit(Some(a), "key.delete", "ok", Some(&tp), None, None, json!({"purge_after": purge_after})).await;
        self.key_card(&tp).await
    }

    pub async fn restore_key(&self, a: &Actor, tp: &str) -> AppResult<Value> {
        a.require("admin")?;
        let r = self.key_row(tp).await?;
        let tp: String = r.get("thumbprint");
        if r.get::<String, _>("status") != "deleted" {
            return Err(AppError::new("bad_request", "Ключ не в статусе «Удалён»"));
        }
        sqlx::query("UPDATE keys SET status='blocked', deleted_at=NULL, purge_after=NULL, updated_at=now() WHERE thumbprint=$1").bind(&tp).execute(&self.meta).await?;
        self.audit(Some(a), "key.restore", "ok", Some(&tp), None, None, json!({})).await;
        self.key_card(&tp).await
    }

    pub async fn purge_key(&self, a: Option<&Actor>, tp: &str, approver: Option<&Actor>) -> AppResult<()> {
        if let Some(a) = a {
            a.require("admin")?;
            match approver {
                Some(ap) if ap.has("admin") && ap.id != a.id => {}
                _ => return Err(AppError::new("second_approver_required", "Уничтожение подтверждает второй администратор")),
            }
        }
        let tp: String = self.key_row(tp).await?.get("thumbprint");
        // crypto-shredding: шифротекст и обёрнутый DEK удаляются, копии в бэкапах без DEK бесполезны
        sqlx::query("DELETE FROM containers WHERE thumbprint=$1").bind(&tp).execute(&self.store).await?;
        sqlx::query("UPDATE keys SET status='purged', pin_ct=NULL, updated_at=now() WHERE thumbprint=$1").bind(&tp).execute(&self.meta).await?;
        sqlx::query("DELETE FROM key_clients WHERE thumbprint=$1").bind(&tp).execute(&self.meta).await?;
        self.invalidate(Some(&tp)).await;
        let by = approver.map(|x| x.id.clone()).unwrap_or_else(|| "retention".into());
        self.audit(a, "key.purge", "ok", Some(&tp), None, None, json!({"approved_by": by})).await;
        Ok(())
    }

    pub async fn housekeeping(&self) -> AppResult<()> {
        let rows = sqlx::query("SELECT thumbprint FROM keys WHERE status='deleted' AND purge_after < now()").fetch_all(&self.meta).await?;
        for r in rows {
            self.purge_key(None, &r.get::<String, _>("thumbprint"), None).await?;
        }
        let ups = sqlx::query("SELECT upload_id FROM uploads WHERE status='pending' AND expires_at < now()").fetch_all(&self.meta).await?;
        for u in ups {
            self.drop_upload(u.get("upload_id"), "expired").await;
        }
        self.cache.run_pending_tasks().await;
        self.metrics.cache_entries.set(self.cache.entry_count() as i64);
        Ok(())
    }

    // ------------------------------------------------------------ Ф-6 аварийная блокировка
    pub async fn emergency_block(&self, a: &Actor, scope: &str) -> AppResult<()> {
        a.require("admin")?;
        sqlx::query("INSERT INTO emergency(scope, created_by) VALUES ($1,$2) ON CONFLICT DO NOTHING").bind(scope).bind(&a.id).execute(&self.meta).await?;
        self.invalidate(None).await;
        self.audit(Some(a), "emergency.block", "ok", None, None, None, json!({"scope": scope})).await;
        Ok(())
    }

    pub async fn emergency_unblock(&self, a: &Actor, scope: &str, approver: Option<&Actor>) -> AppResult<()> {
        a.require("admin")?;
        match approver {
            Some(ap) if ap.has("admin") && ap.id != a.id => {}
            _ => return Err(AppError::new("second_approver_required", "Снятие аварийной блокировки подтверждает второй администратор")),
        }
        sqlx::query("DELETE FROM emergency WHERE scope=$1").bind(scope).execute(&self.meta).await?;
        self.audit(Some(a), "emergency.unblock", "ok", None, None, None, json!({"scope": scope, "approved_by": approver.unwrap().id})).await;
        Ok(())
    }

    // ------------------------------------------------------------ использование ключа
    async fn usable_key(&self, a: &Actor, tp: &str, op: &str) -> AppResult<String> {
        let r = sqlx::query("SELECT k.thumbprint, k.status, k.not_before, k.not_after, c.can_sign, c.can_decrypt FROM keys k LEFT JOIN key_clients c ON c.thumbprint=k.thumbprint AND c.client_id=$2 WHERE k.thumbprint=$1")
            .bind(tp.to_uppercase()).bind(&a.id).fetch_optional(&self.meta).await?;
        let Some(r) = r else { return Err(AppError::code("key_not_found")) };
        let status: String = r.get("status");
        if status == "purged" {
            return Err(AppError::code("key_not_found"));
        }
        let right: Option<bool> = r.get(if op == "sign" { "can_sign" } else { "can_decrypt" });
        if right != Some(true) {
            return Err(AppError::new("forbidden", format!("Системе не разрешена операция {op} этим ключом")));
        }
        let emerg = sqlx::query("SELECT 1 FROM emergency WHERE scope='all' OR scope=$1").bind(format!("client:{}", a.id)).fetch_optional(&self.meta).await?;
        if emerg.is_some() {
            return Err(AppError::new("emergency_block", "Действует аварийная блокировка"));
        }
        match status.as_str() {
            "blocked" => return Err(AppError::code("key_blocked")),
            "deleted" => return Err(AppError::code("key_deleted")),
            _ => {}
        }
        if r.get::<DateTime<Utc>, _>("not_after") < now() {
            return Err(AppError::code("cert_expired"));
        }
        if r.get::<DateTime<Utc>, _>("not_before") > now() {
            return Err(AppError::code("cert_not_yet_valid"));
        }
        let tp: String = r.get("thumbprint");
        self.rate(a, &tp)?;
        Ok(tp)
    }

    // ------------------------------------------------------------ Ф-2 подпись
    #[allow(clippy::too_many_arguments)]
    pub async fn sign(&self, a: &Actor, tp: &str, input: SignInput, detached: bool, encoding: &str, ext: Option<String>, filename: Option<String>) -> AppResult<Output> {
        a.require("signer")?;
        let ext = ext.unwrap_or_else(|| if detached { "sgn".into() } else { "p7m".into() }).trim_start_matches('.').to_lowercase();
        if !self.cfg.sign_ext.contains(&ext) || (ext == "p7m" && detached) {
            return Err(AppError::new("unsupported_ext", format!("Допустимо: {}; p7m — только для прикреплённой", self.cfg.sign_ext.join(", "))));
        }
        if !matches!(encoding, "der" | "base64" | "pem") {
            return Err(AppError::new("bad_request", "encoding: der | base64 | pem"));
        }
        if matches!(input, SignInput::Hash(_)) && !detached {
            return Err(AppError::new("hash_requires_detached", "По хэшу можно сделать только отделённую подпись"));
        }
        let tp = self.usable_key(a, tp, "sign").await?;
        let ctx = self.ctx(&tp).await?;
        let prov = self.prov.clone();
        let mode = if matches!(input, SignInput::Hash(_)) { "hash" } else { "data" };
        let max_file = self.cfg.max_file;
        let t0 = std::time::Instant::now();
        let res = blocking(move || {
            let (d, content) = match input {
                SignInput::Hash(h) => {
                    if h.len() != ctx.cert.digest_len {
                        return Err(AppError::new("bad_hash_length", format!("Для {} нужен хэш {} байт (ГОСТ Р 34.11-2012)", ctx.cert.key_alg, ctx.cert.digest_len)));
                    }
                    (h, None)
                }
                SignInput::Data(data) => {
                    if data.len() > max_file {
                        return Err(AppError::code("too_large"));
                    }
                    let d = prov.digest(ctx.cert.digest_oid, &data)?;
                    (d, if detached { None } else { Some(data) })
                }
            };
            let cms = Self::cms_sign(&*prov, &*ctx.key, &ctx.cert, &ctx.tpl, ctx.reverse, &d, content.as_deref())?;
            Ok((cms, d))
        })
        .await;
        self.metrics.op_seconds.with_label_values(&["sign"]).observe(t0.elapsed().as_secs_f64());
        let (cms, d) = match res {
            Ok(v) => v,
            Err(e) => {
                self.audit(Some(a), "sign", "error", Some(&tp), None, Some(e.code), json!({})).await;
                return Err(e);
            }
        };
        self.touch(&tp).await;
        self.audit(Some(a), "sign", "ok", Some(&tp), Some(&d), None, json!({"detached": detached, "ext": ext, "filename": filename, "mode": mode})).await;
        let body = encode(cms, encoding);
        let content_type = if encoding != "der" { "text/plain; charset=us-ascii" } else if detached { "application/pkcs7-signature" } else { "application/pkcs7-mime" };
        Ok(Output { body, content_type, filename: format!("{}.{}", filename.unwrap_or_else(|| "document".into()), ext) })
    }

    // ------------------------------------------------------------ Ф-8 шифрование
    pub async fn encrypt(&self, a: &Actor, data: Vec<u8>, recipients: Vec<String>, certs: Vec<String>, cipher: &str, encoding: &str, ext: &str) -> AppResult<Output> {
        let ext = ext.trim_start_matches('.').to_lowercase();
        if !self.cfg.enc_ext.contains(&ext) {
            return Err(AppError::new("unsupported_ext", format!("Допустимо: {}", self.cfg.enc_ext.join(", "))));
        }
        if !matches!(encoding, "der" | "base64" | "pem") {
            return Err(AppError::new("bad_request", "encoding: der | base64 | pem"));
        }
        let mut ders = Vec::new();
        for tp in &recipients {
            ders.push(self.key_row(tp).await?.get::<Vec<u8>, _>("cert_der"));
        }
        for c in &certs {
            let d = der::to_der(c.as_bytes()).ok_or_else(|| AppError::new("bad_request", "Не удалось прочитать сертификат получателя"))?;
            cert::parse(&d)?;
            ders.push(d);
        }
        if ders.is_empty() {
            return Err(AppError::new("bad_request", "Нужен хотя бы один получатель"));
        }
        if data.len() > self.cfg.max_file {
            return Err(AppError::code("too_large"));
        }
        let prov = self.prov.clone();
        let cipher_s = cipher.to_string();
        let size = data.len();
        let sha = sha2::Sha256::digest_bytes(&data);
        let rec: Vec<String> = ders.iter().map(|d| cert::thumbprint(d)).collect();
        let t0 = std::time::Instant::now();
        let out = blocking(move || prov.encrypt(&data, &ders, &cipher_s)).await?;
        self.metrics.op_seconds.with_label_values(&["encrypt"]).observe(t0.elapsed().as_secs_f64());
        self.audit(Some(a), "encrypt", "ok", None, Some(&sha), None, json!({"size": size, "cipher": cipher, "recipients": rec})).await;
        Ok(Output {
            body: encode(out, encoding),
            content_type: if encoding == "der" { "application/pkcs7-mime" } else { "text/plain; charset=us-ascii" },
            filename: format!("data.{ext}"),
        })
    }

    pub async fn decrypt(&self, a: &Actor, tp: &str, blob: Vec<u8>) -> AppResult<Zeroizing<Vec<u8>>> {
        a.require("signer")?;
        let tp = self.usable_key(a, tp, "decrypt").await?;
        let der = der::to_der(&blob).ok_or_else(|| AppError::new("bad_request", "Ожидается CMS в DER, Base64 или PEM"))?;
        let ctx = self.ctx(&tp).await?;
        let t0 = std::time::Instant::now();
        let res = blocking(move || ctx.key.decrypt(&der)).await;
        self.metrics.op_seconds.with_label_values(&["decrypt"]).observe(t0.elapsed().as_secs_f64());
        match res {
            Ok(out) => {
                self.touch(&tp).await;
                self.audit(Some(a), "decrypt", "ok", Some(&tp), None, None, json!({"size": out.len()})).await;
                Ok(out)
            }
            Err(e) => {
                self.audit(Some(a), "decrypt", "error", Some(&tp), None, Some(e.code), json!({})).await;
                Err(e)
            }
        }
    }

    // ------------------------------------------------------------ Ф-7 аудит
    pub async fn audit_log(&self, a: &Actor, tp: Option<String>, op: Option<String>, limit: i64) -> AppResult<Value> {
        if !(a.has("auditor") || a.has("admin")) {
            return Err(AppError::code("forbidden"));
        }
        let rows = sqlx::query("SELECT id, ts, request_id, actor, op, thumbprint, doc_hash, details, result, error_code FROM audit WHERE ($1::text IS NULL OR thumbprint=$1) AND ($2::text IS NULL OR op=$2) ORDER BY id DESC LIMIT $3")
            .bind(tp).bind(op).bind(limit.clamp(1, 10000)).fetch_all(&self.meta).await?;
        Ok(Value::Array(rows.iter().map(|r| json!({
            "id": r.get::<i64,_>("id"), "ts": r.get::<DateTime<Utc>,_>("ts"), "request_id": r.get::<Option<String>,_>("request_id"),
            "actor": r.get::<Option<String>,_>("actor"), "op": r.get::<String,_>("op"), "thumbprint": r.get::<Option<String>,_>("thumbprint"),
            "doc_hash": r.get::<Option<String>,_>("doc_hash"), "details": r.get::<Option<sqlx::types::Json<Value>>,_>("details").map(|j| j.0),
            "result": r.get::<String,_>("result"), "error_code": r.get::<Option<String>,_>("error_code"),
        })).collect()))
    }

    pub async fn refresh_gauges(&self) {
        if let Ok(rows) = sqlx::query("SELECT status, count(*) AS n FROM keys GROUP BY status").fetch_all(&self.meta).await {
            self.metrics.keys.reset();
            for r in rows {
                self.metrics.keys.with_label_values(&[&r.get::<String, _>("status")]).set(r.get::<i64, _>("n"));
            }
        }
        if let Ok(r) = sqlx::query("SELECT count(*) AS n FROM keys WHERE status='active' AND not_after < now() + interval '30 days'").fetch_one(&self.meta).await {
            self.metrics.keys_expiring.set(r.get::<i64, _>("n"));
        }
        self.metrics.cache_entries.set(self.cache.entry_count() as i64);
    }

    /// Обновить last_used_at не чаще раза в минуту на ключ.
    async fn touch(&self, tp: &str) {
        {
            let mut m = self.last_used.lock().unwrap();
            if let Some(t) = m.get(tp) {
                if t.elapsed() < std::time::Duration::from_secs(60) {
                    return;
                }
            }
            m.insert(tp.to_string(), std::time::Instant::now());
        }
        let _ = sqlx::query("UPDATE keys SET last_used_at=now() WHERE thumbprint=$1").bind(tp).execute(&self.meta).await;
    }

    pub fn transport_certificate(&self) -> Option<Vec<u8>> {
        self.transport.as_ref().map(|t| der::pem("CERTIFICATE", &t.cert.der))
    }
}

fn encode(der_bytes: Vec<u8>, encoding: &str) -> Vec<u8> {
    match encoding {
        "base64" => B64.encode(der_bytes).into_bytes(),
        "pem" => der::pem("CMS", &der_bytes),
        _ => der_bytes,
    }
}

trait DigestBytes {
    fn digest_bytes(data: &[u8]) -> Vec<u8>;
}
impl DigestBytes for sha2::Sha256 {
    fn digest_bytes(data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }
}
