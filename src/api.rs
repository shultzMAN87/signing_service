//! HTTP API (ТЗ, раздел 4). Префикс /api/v1.
use crate::error::{AppError, AppResult};
use crate::service::{Actor, App, ClientRight, SignInput};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, MatchedPath, Multipart, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

type S = State<Arc<App>>;

#[derive(Clone)]
struct Rid(String);

/// Аутентифицированный вызов (Bearer-токен из ESIGN_CLIENTS).
struct Caller(Actor);

impl FromRequestParts<Arc<App>> for Caller {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut axum::http::request::Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        let rid = parts.extensions.get::<Rid>().map(|r| r.0.clone()).unwrap_or_default();
        actor_from(app, &parts.headers, "authorization", &rid).map(Caller).ok_or_else(|| AppError::code("unauthenticated"))
    }
}

fn actor_from(app: &App, h: &HeaderMap, name: &str, rid: &str) -> Option<Actor> {
    let v = h.get(name)?.to_str().ok()?;
    let token = v.strip_prefix("Bearer ").unwrap_or(v).trim();
    app.cfg.clients.get(token).map(|c| Actor { id: c.id.clone(), roles: c.roles.clone(), request_id: rid.to_string() })
}

fn approver(app: &App, h: &HeaderMap) -> Option<Actor> {
    actor_from(app, h, "x-approver-token", "")
}

fn file_response(o: crate::service::Output) -> Response {
    const KEEP: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'.').remove(b'-').remove(b'_').remove(b'~');
    let enc = percent_encoding::utf8_percent_encode(&o.filename, KEEP).to_string();
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(o.content_type)),
            (header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{enc}")).unwrap()),
        ],
        o.body,
    )
        .into_response()
}

/// Поля запроса: JSON или multipart (файл — в поле file / container).
struct Payload {
    fields: HashMap<String, Value>,
    file: Option<(Option<String>, Bytes)>,
}

impl Payload {
    fn s(&self, k: &str) -> Option<String> {
        match self.fields.get(k)? {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            v => Some(v.to_string()),
        }
    }
    fn b(&self, k: &str, default: bool) -> bool {
        match self.fields.get(k) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => matches!(s.to_lowercase().as_str(), "1" | "true" | "yes" | "да"),
            _ => default,
        }
    }
    fn list(&self, k: &str) -> Vec<String> {
        match self.fields.get(k) {
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            Some(Value::String(s)) if s.trim_start().starts_with('[') => serde_json::from_str(s).unwrap_or_default(),
            Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
            _ => vec![],
        }
    }
}

impl FromRequest<Arc<App>> for Payload {
    type Rejection = AppError;
    async fn from_request(req: Request, app: &Arc<App>) -> Result<Self, Self::Rejection> {
        let ct = req.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        if ct.starts_with("multipart/form-data") {
            let mut mp = Multipart::from_request(req, app).await.map_err(|e| AppError::new("bad_request", e.to_string()))?;
            let mut fields = HashMap::new();
            let mut file = None;
            while let Some(f) = mp.next_field().await.map_err(|e| AppError::new("bad_request", e.to_string()))? {
                let name = f.name().unwrap_or("").to_string();
                if name == "file" || name == "container" {
                    let fname = f.file_name().map(String::from);
                    let data = f.bytes().await.map_err(|_| AppError::code("too_large"))?;
                    file = Some((fname, data));
                } else {
                    fields.insert(name, Value::String(f.text().await.map_err(|e| AppError::new("bad_request", e.to_string()))?));
                }
            }
            Ok(Self { fields, file })
        } else if ct.starts_with("application/json") {
            let Json(v): Json<HashMap<String, Value>> = Json::from_request(req, app).await.map_err(|e| AppError::new("bad_request", e.body_text()))?;
            Ok(Self { fields: v, file: None })
        } else {
            Err(AppError::new("bad_request", "Ожидается application/json или multipart/form-data"))
        }
    }
}

fn clients_of(p: &Payload) -> AppResult<Vec<ClientRight>> {
    match p.fields.get("clients") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => serde_json::from_value(Value::Array(a.clone())).map_err(|e| AppError::new("bad_request", e.to_string())),
        Some(Value::String(s)) if s.trim_start().starts_with('[') => serde_json::from_str(s).map_err(|e| AppError::new("bad_request", e.to_string())),
        Some(_) => Ok(p.list("clients").into_iter().map(|id| ClientRight { id, sign: true, decrypt: false }).collect()),
    }
}

// ---------------------------------------------------------------- служебное
async fn health(State(app): S) -> Json<Value> {
    Json(json!({"status": "ok", "provider": app.prov.name(), "cache": app.cache.entry_count()}))
}

async fn metrics(State(app): S, h: HeaderMap) -> Response {
    if let Ok(tok) = std::env::var("ESIGN_METRICS_TOKEN") {
        if h.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {tok}")) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    app.refresh_gauges().await;
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], app.metrics.render()).into_response()
}

async fn transport_certificate(State(app): S) -> AppResult<Response> {
    let pem = app.transport_certificate().ok_or_else(|| AppError::new("key_not_found", "Транспортный ключ не настроен"))?;
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], pem).into_response())
}

// ---------------------------------------------------------------- загрузка ключа
async fn upload_container(State(app): S, Caller(a): Caller, p: Payload) -> AppResult<(StatusCode, Json<Value>)> {
    if p.fields.contains_key("pin") {
        return Err(AppError::new("bad_request", "PIN передаётся только вторым запросом"));
    }
    let (_, data) = p.file.clone().ok_or_else(|| AppError::new("bad_request", "Нужен файл container"))?;
    let v = app.upload_container(&a, data.to_vec(), &p.s("key_type").unwrap_or_else(|| "organization".into()), p.s("owner_login"), clients_of(&p)?).await?;
    Ok((StatusCode::CREATED, Json(v)))
}

#[derive(Deserialize)]
struct PinBody {
    pin: Option<String>,
    pin_envelope: Option<String>,
}

async fn upload_pin(State(app): S, Caller(a): Caller, Path(id): Path<Uuid>, Json(b): Json<PinBody>) -> AppResult<(StatusCode, Json<Value>)> {
    let v = app.upload_pin(&a, id, b.pin.map(Zeroizing::new), b.pin_envelope).await?;
    Ok((StatusCode::CREATED, Json(v)))
}

// ---------------------------------------------------------------- ключи
async fn list_keys(State(app): S, Caller(a): Caller) -> AppResult<Json<Value>> {
    Ok(Json(app.list_keys(&a).await?))
}
async fn get_key(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(app.get_key(&a, &tp).await?))
}
async fn get_cert(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Response> {
    let der = app.certificate(&a, &tp).await?;
    Ok(file_response(crate::service::Output { body: der, content_type: "application/pkix-cert", filename: format!("{}.cer", tp.to_uppercase()) }))
}
async fn block(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(app.set_status(&a, &tp, "blocked").await?))
}
async fn unblock(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(app.set_status(&a, &tp, "active").await?))
}
async fn rotate_pin(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(app.rotate_pin(&a, &tp).await?))
}
async fn set_clients(State(app): S, Caller(a): Caller, Path(tp): Path<String>, p: Payload) -> AppResult<Json<Value>> {
    Ok(Json(app.set_clients(&a, &tp, clients_of(&p)?).await?))
}
#[derive(Deserialize)]
struct PurgeQ {
    #[serde(default)]
    purge: bool,
}
async fn delete_key(State(app): S, Caller(a): Caller, Path(tp): Path<String>, Query(q): Query<PurgeQ>, h: HeaderMap) -> AppResult<Json<Value>> {
    if q.purge {
        app.purge_key(Some(&a), &tp, approver(&app, &h).as_ref()).await?;
        return Ok(Json(json!({"thumbprint": tp.to_uppercase(), "status": "purged"})));
    }
    Ok(Json(app.delete_key(&a, &tp).await?))
}
async fn restore_key(State(app): S, Caller(a): Caller, Path(tp): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(app.restore_key(&a, &tp).await?))
}

// ---------------------------------------------------------------- подпись / шифрование
fn b64(s: &str) -> AppResult<Vec<u8>> {
    B64.decode(s.trim()).map_err(|_| AppError::new("bad_request", "Ожидается Base64"))
}

async fn sign(State(app): S, Caller(a): Caller, p: Payload) -> AppResult<Response> {
    let tp = p.s("thumbprint").ok_or_else(|| AppError::new("bad_request", "Нужен thumbprint"))?;
    let sources = [p.s("hash").is_some(), p.s("data").is_some(), p.file.is_some()].iter().filter(|x| **x).count();
    if sources != 1 {
        return Err(AppError::new("bad_request", "Передайте ровно одно: hash, data или file"));
    }
    let input = if let Some(h) = p.s("hash") {
        SignInput::Hash(b64(&h)?)
    } else if let Some(d) = p.s("data") {
        SignInput::Data(b64(&d)?)
    } else {
        SignInput::Data(p.file.as_ref().unwrap().1.to_vec())
    };
    let filename = p.s("filename").or_else(|| p.file.as_ref().and_then(|f| f.0.clone()));
    let out = app.sign(&a, &tp, input, p.b("detached", true), &p.s("encoding").unwrap_or_else(|| "der".into()), p.s("ext"), filename).await?;
    Ok(file_response(out))
}

async fn encrypt(State(app): S, Caller(a): Caller, p: Payload) -> AppResult<Response> {
    let data = if let Some((_, f)) = &p.file {
        f.to_vec()
    } else if let Some(t) = p.s("text") {
        t.into_bytes()
    } else if let Some(d) = p.s("data") {
        b64(&d)?
    } else {
        return Err(AppError::new("bad_request", "Нужно text, data или file"));
    };
    let certs = match p.fields.get("recipient_certs") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => vec![],
    };
    let out = app
        .encrypt(&a, data, p.list("recipients"), certs, &p.s("cipher").unwrap_or_else(|| "default".into()), &p.s("encoding").unwrap_or_else(|| "der".into()), &p.s("ext").unwrap_or_else(|| "p7m".into()))
        .await?;
    Ok(file_response(out))
}

async fn decrypt(State(app): S, Caller(a): Caller, p: Payload) -> AppResult<Response> {
    let tp = p.s("thumbprint").ok_or_else(|| AppError::new("bad_request", "Нужен thumbprint"))?;
    let blob = match (&p.file, p.s("data")) {
        (Some((_, f)), _) => f.to_vec(),
        (None, Some(d)) => d.into_bytes(),
        _ => return Err(AppError::new("bad_request", "Нужно data или file")),
    };
    let out = app.decrypt(&a, &tp, blob).await?;
    if p.b("as_text", false) {
        return Ok(Json(json!({"text": String::from_utf8_lossy(&out)})).into_response());
    }
    Ok(file_response(crate::service::Output { body: out.to_vec(), content_type: "application/octet-stream", filename: "decrypted.bin".into() }))
}

// ---------------------------------------------------------------- аварийная блокировка, аудит
#[derive(Deserialize, Default)]
struct ScopeBody {
    scope: Option<String>,
}
async fn emergency_block(State(app): S, Caller(a): Caller, body: Option<Json<ScopeBody>>) -> AppResult<Json<Value>> {
    let scope = body.and_then(|b| b.0.scope).unwrap_or_else(|| "all".into());
    app.emergency_block(&a, &scope).await?;
    Ok(Json(json!({"scope": scope, "status": "blocked"})))
}
async fn emergency_unblock(State(app): S, Caller(a): Caller, h: HeaderMap, body: Option<Json<ScopeBody>>) -> AppResult<Json<Value>> {
    let scope = body.and_then(|b| b.0.scope).unwrap_or_else(|| "all".into());
    app.emergency_unblock(&a, &scope, approver(&app, &h).as_ref()).await?;
    Ok(Json(json!({"scope": scope, "status": "unblocked"})))
}
#[derive(Deserialize)]
struct AuditQ {
    thumbprint: Option<String>,
    op: Option<String>,
    limit: Option<i64>,
}
async fn audit(State(app): S, Caller(a): Caller, Query(q): Query<AuditQ>) -> AppResult<Json<Value>> {
    Ok(Json(app.audit_log(&a, q.thumbprint, q.op, q.limit.unwrap_or(200)).await?))
}

// ---------------------------------------------------------------- middleware
async fn mw(State(app): S, mut req: Request, next: Next) -> Response {
    let rid = req.headers().get("x-request-id").and_then(|v| v.to_str().ok()).map(String::from).unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let route = req.extensions().get::<MatchedPath>().map(|m| m.as_str().to_string()).unwrap_or_else(|| "other".into());
    req.extensions_mut().insert(Rid(rid.clone()));
    let mut resp = next.run(req).await;
    // request_id в теле ошибки
    if let Some(code) = resp.extensions().get::<crate::error::ErrorCode>().map(|c| c.0) {
        let status = resp.status();
        let body = axum::body::to_bytes(std::mem::take(resp.body_mut()), 1 << 20).await.unwrap_or_default();
        let mut v: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({"code": code}));
        v["request_id"] = Value::String(rid.clone());
        resp = (status, Json(v)).into_response();
        app.metrics.ops.with_label_values(&[route.as_str(), code]).inc();
    }
    app.metrics.http.with_label_values(&[route.as_str(), resp.status().as_str()]).inc();
    resp.headers_mut().insert("x-request-id", HeaderValue::from_str(&rid).unwrap());
    resp
}

pub fn router(app: Arc<App>) -> Router {
    let limit = app.cfg.max_file + 2 * 1024 * 1024;
    let v1 = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/transport-certificate", get(transport_certificate))
        .route("/keys/uploads", post(upload_container))
        .route("/keys/uploads/{id}/pin", post(upload_pin))
        .route("/keys", get(list_keys))
        .route("/keys/{tp}", get(get_key).delete(delete_key))
        .route("/keys/{tp}/certificate", get(get_cert))
        .route("/keys/{tp}/block", post(block))
        .route("/keys/{tp}/unblock", post(unblock))
        .route("/keys/{tp}/pin/rotate", post(rotate_pin))
        .route("/keys/{tp}/clients", put(set_clients))
        .route("/keys/{tp}/restore", post(restore_key))
        .route("/sign", post(sign))
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
        .route("/emergency/block", post(emergency_block))
        .route("/emergency/unblock", post(emergency_unblock))
        .route("/audit", get(audit));
    Router::new()
        .nest("/api/v1", v1)
        .route("/metrics", get(metrics))
        .layer(middleware::from_fn_with_state(app.clone(), mw))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(app)
}
