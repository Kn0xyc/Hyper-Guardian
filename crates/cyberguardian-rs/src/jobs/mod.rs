use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use sqlx::SqlitePool;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};

use crate::{
    adapters::{NmapAdapter, ScanRequest, ToolAdapter},
    config::AppConfig,
    security::in_scope,
};

#[derive(Debug, Clone)]
pub struct QueuedJob {
    pub id: i64,
    pub target: String,
    pub tool: String,
    pub profile: String,
}

#[derive(Debug, Default)]
pub struct JobRunnerState {
    pub running: usize,
}

#[derive(Debug)]
pub struct RateLimiter {
    limit_per_minute: usize,
    requests: VecDeque<Instant>,
}

impl RateLimiter {
    pub fn new(limit_per_minute: usize) -> Self {
        Self {
            limit_per_minute,
            requests: VecDeque::new(),
        }
    }

    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        while let Some(front) = self.requests.front() {
            if now.duration_since(*front) > Duration::from_secs(60) {
                self.requests.pop_front();
            } else {
                break;
            }
        }
        if self.requests.len() >= self.limit_per_minute {
            return false;
        }
        self.requests.push_back(now);
        true
    }
}

pub async fn worker_loop(
    pool: SqlitePool,
    mut rx: mpsc::Receiver<QueuedJob>,
    runner_state: Arc<Mutex<JobRunnerState>>,
    cfg: Arc<AppConfig>,
) {
    while let Some(job) = rx.recv().await {
        {
            let mut lock = runner_state.lock().await;
            lock.running += 1;
        }

        if !in_scope(&job.target, &cfg.scope_allowlist) {
            let _ = sqlx::query("UPDATE jobs SET status='rejected_scope' WHERE id=?")
                .bind(job.id)
                .execute(&pool)
                .await;
            decrement_running(&runner_state).await;
            continue;
        }

        let update = sqlx::query("UPDATE jobs SET status='running' WHERE id=?")
            .bind(job.id)
            .execute(&pool)
            .await;

        if let Err(e) = update {
            error!(error = %e, job_id = job.id, "failed status update");
            decrement_running(&runner_state).await;
            continue;
        }

        let adapter = NmapAdapter;
        let result = adapter
            .run(ScanRequest {
                target: job.target.clone(),
                profile: job.profile.clone(),
            })
            .await;

        match result {
            Ok(scan) => {
                let _ = sqlx::query(
                    "INSERT INTO scans(tool, target, profile, status, started_at, ended_at) VALUES(?, ?, ?, 'done', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                )
                .bind(&job.tool)
                .bind(&job.target)
                .bind(&job.profile)
                .execute(&pool)
                .await;

                for asset in &scan.assets {
                    let _ = sqlx::query("INSERT INTO assets(ip, hostname, created_at) VALUES(?, ?, CURRENT_TIMESTAMP)")
                        .bind(&asset.ip)
                        .bind(&asset.hostname)
                        .execute(&pool)
                        .await;
                }

                for finding in &scan.findings {
                    let inserted = sqlx::query(
                        "INSERT INTO findings(scan_id, asset_id, key, severity, title, description, created_at) VALUES(NULL, NULL, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    )
                    .bind(&finding.key)
                    .bind(&finding.severity)
                    .bind(&finding.title)
                    .bind(&finding.description)
                    .execute(&pool)
                    .await;

                    if let Ok(res) = inserted {
                        let finding_id = res.last_insert_rowid();
                        if let Some(evidence) =
                            scan.evidence.iter().find(|e| e.finding_key == finding.key)
                        {
                            let _ = sqlx::query(
                                "INSERT INTO evidence(finding_id, raw_data) VALUES(?, ?)",
                            )
                            .bind(finding_id)
                            .bind(&evidence.raw)
                            .execute(&pool)
                            .await;
                        }
                    }
                }

                info!(
                    job_id = job.id,
                    findings = scan.findings.len(),
                    "scan completed"
                );
                let _ = sqlx::query("UPDATE jobs SET status='done' WHERE id=?")
                    .bind(job.id)
                    .execute(&pool)
                    .await;
            }
            Err(e) => {
                error!(error = %e, job_id = job.id, "scan failed");
                let _ = sqlx::query("UPDATE jobs SET status='failed' WHERE id=?")
                    .bind(job.id)
                    .execute(&pool)
                    .await;
            }
        }

        let _ = sqlx::query(
            "INSERT INTO audit_log(action, actor, details, created_at) VALUES('launch_tool','system', ?, CURRENT_TIMESTAMP)",
        )
        .bind(format!("tool={} target={}", job.tool, job.target))
        .execute(&pool)
        .await;

        decrement_running(&runner_state).await;
    }
}

async fn decrement_running(runner_state: &Arc<Mutex<JobRunnerState>>) {
    let mut lock = runner_state.lock().await;
    lock.running = lock.running.saturating_sub(1);
}
