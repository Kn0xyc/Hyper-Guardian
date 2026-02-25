mod adapters;
mod api;
mod auth;
mod config;
mod db;
mod jobs;
mod models;
mod parser;
mod security;
mod ui;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{
    routing::{get, post},
    Router,
};
use tokio::sync::{mpsc, Mutex};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::{
    api::{create_job, health, list_assets, list_findings, list_jobs, login},
    auth::SessionStore,
    config::AppConfig,
    jobs::{worker_loop, JobRunnerState, RateLimiter},
};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub sessions: SessionStore,
    pub queue: mpsc::Sender<jobs::QueuedJob>,
    pub runner_state: Arc<Mutex<JobRunnerState>>,
    pub config: Arc<AppConfig>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Arc::new(AppConfig::load()?);

    let pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;

    let (tx, rx) = mpsc::channel(128);
    let runner_state = Arc::new(Mutex::new(JobRunnerState::default()));
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(30)));

    let state = AppState {
        pool: pool.clone(),
        sessions: SessionStore::default(),
        queue: tx.clone(),
        runner_state: runner_state.clone(),
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
    };

    tokio::spawn(worker_loop(pool.clone(), rx, runner_state, config.clone()));

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/jobs", get(list_jobs).post(create_job))
        .route("/api/assets", get(list_assets))
        .route("/api/findings", get(list_findings))
        .route("/", get(ui::index))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("invalid host/port")?;

    info!(%addr, "CyberGuardian-RS listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
}
