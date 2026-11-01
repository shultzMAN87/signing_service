//! Метрики Prometheus (ТЗ, раздел 7).
use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};

pub struct Metrics {
    pub registry: Registry,
    pub http: IntCounterVec,
    pub ops: IntCounterVec,
    pub op_seconds: HistogramVec,
    pub cache_hits: IntCounter,
    pub cache_misses: IntCounter,
    pub cache_entries: IntGauge,
    pub keys: IntGaugeVec,
    pub keys_expiring: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let r = Registry::new_custom(Some("esign".into()), None).unwrap();
        let http = IntCounterVec::new(Opts::new("http_requests_total", "HTTP-запросы"), &["route", "status"]).unwrap();
        let ops = IntCounterVec::new(Opts::new("operations_total", "Операции сервиса по результату"), &["op", "result"]).unwrap();
        let op_seconds = HistogramVec::new(
            HistogramOpts::new("operation_seconds", "Длительность операций")
                .buckets(vec![0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0]),
            &["op"],
        )
        .unwrap();
        let cache_hits = IntCounter::new("cache_hits_total", "Попадания в кэш ключей").unwrap();
        let cache_misses = IntCounter::new("cache_misses_total", "Промахи кэша (загрузка ключа)").unwrap();
        let cache_entries = IntGauge::new("cache_entries", "Ключей в кэше").unwrap();
        let keys = IntGaugeVec::new(Opts::new("keys", "Ключи по статусам"), &["status"]).unwrap();
        let keys_expiring = IntGauge::new("keys_expiring_30d", "Активные ключи, сертификат которых истекает в течение 30 дней").unwrap();
        for c in [
            Box::new(http.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(ops.clone()),
            Box::new(op_seconds.clone()),
            Box::new(cache_hits.clone()),
            Box::new(cache_misses.clone()),
            Box::new(cache_entries.clone()),
            Box::new(keys.clone()),
            Box::new(keys_expiring.clone()),
        ] {
            r.register(c).unwrap();
        }
        Self { registry: r, http, ops, op_seconds, cache_hits, cache_misses, cache_entries, keys, keys_expiring }
    }

    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }
}
