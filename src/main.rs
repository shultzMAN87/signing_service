//! Сервис подписания ГОСТ ЭП — тестовая сборка по ТЗ.
mod api;
mod cert;
mod config;
mod crypto;
mod der;
mod error;
mod kms;
mod metrics;
mod service;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .init();
    let cfg = match config::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Ошибка конфигурации: {e}");
            std::process::exit(2);
        }
    };
    let listen = cfg.listen.clone();
    // Зависимости (БД, Vault) могут подниматься дольше сервиса — ждём до 60 с.
    let mut app = None;
    for attempt in 1..=30 {
        match service::App::new(cfg.clone()).await {
            Ok(a) => {
                app = Some(a);
                break;
            }
            Err(e) if e.code == "dependency_unavailable" && attempt < 30 => {
                tracing::warn!(attempt, error = %e, "зависимости недоступны, повтор через 2 с");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                eprintln!("Не удалось запустить сервис: {e}");
                std::process::exit(1);
            }
        }
    }
    let app: Arc<service::App> = app.unwrap();
    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                t.tick().await;
                if let Err(e) = app.housekeeping().await {
                    tracing::warn!(error = %e, "housekeeping");
                }
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(&listen).await.expect("bind");
    tracing::info!(%listen, "HTTP API слушает");
    axum::serve(listener, api::router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
