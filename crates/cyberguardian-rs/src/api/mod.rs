use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::Role,
    jobs::QueuedJob,
    models::{AssetRecord, FindingRecord, Job},
    security::in_scope,
    AppState,
};

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "service": "CyberGuardian-RS"}))
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    token: String,
    role: Role,
}

pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    match state.sessions.login(&req.username, &req.password).await {
        Some((token, role)) => {
            (StatusCode::OK, Json(LoginResponse { token, role })).into_response()
        }
        None => (StatusCode::UNAUTHORIZED, "invalid credentials").into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    target: String,
    tool: String,
    profile: String,
}

pub async fn list_jobs(State(state): State<AppState>, req: Request) -> Response {
    if let Err(resp) =
        require_role(&state, &req, &[Role::Admin, Role::Operator, Role::Viewer]).await
    {
        return resp;
    }

    let rows = sqlx::query_as::<_, Job>(
        "SELECT id, target, tool, profile, status, created_at FROM jobs ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(items) => Json(items).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn list_assets(State(state): State<AppState>, req: Request) -> Response {
    if let Err(resp) =
        require_role(&state, &req, &[Role::Admin, Role::Operator, Role::Viewer]).await
    {
        return resp;
    }

    let rows = sqlx::query_as::<_, AssetRecord>(
        "SELECT id, ip, hostname, created_at FROM assets ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(items) => Json(items).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn list_findings(State(state): State<AppState>, req: Request) -> Response {
    if let Err(resp) =
        require_role(&state, &req, &[Role::Admin, Role::Operator, Role::Viewer]).await
    {
        return resp;
    }

    let rows = sqlx::query_as::<_, FindingRecord>(
        "SELECT id, key, severity, title, description, created_at FROM findings ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(items) => Json(items).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn create_job(
    State(state): State<AppState>,
    req: Request,
    Json(payload): Json<CreateJobRequest>,
) -> Response {
    if let Err(resp) = require_role(&state, &req, &[Role::Admin, Role::Operator]).await {
        return resp;
    }

    if !in_scope(&payload.target, &state.config.scope_allowlist) {
        return (StatusCode::FORBIDDEN, "target out of scope").into_response();
    }

    {
        let mut limiter = state.rate_limiter.lock().await;
        if !limiter.allow() {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
        }
    }

    let insert = sqlx::query(
        "INSERT INTO jobs(target, tool, profile, status, created_at) VALUES(?, ?, ?, 'queued', CURRENT_TIMESTAMP)",
    )
    .bind(&payload.target)
    .bind(&payload.tool)
    .bind(&payload.profile)
    .execute(&state.pool)
    .await;

    let job_id = match insert {
        Ok(r) => r.last_insert_rowid(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let _ = sqlx::query(
        "INSERT INTO audit_log(action, actor, details, created_at) VALUES('create_job', ?, ?, CURRENT_TIMESTAMP)",
    )
    .bind("api")
    .bind(format!("job_id={job_id} target={}", payload.target))
    .execute(&state.pool)
    .await;

    let _ = state
        .queue
        .send(QueuedJob {
            id: job_id,
            target: payload.target,
            tool: payload.tool,
            profile: payload.profile,
        })
        .await;

    (StatusCode::CREATED, Json(serde_json::json!({"id": job_id}))).into_response()
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    if let Some(token) = bearer(&req) {
        if let Some(session) = state.sessions.get(&token).await {
            req.extensions_mut().insert(session);
            return next.run(req).await;
        }
    }
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

async fn require_role(state: &AppState, req: &Request, allowed: &[Role]) -> Result<(), Response> {
    let token =
        bearer(req).ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer").into_response())?;
    let sess = state
        .sessions
        .get(&token)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid token").into_response())?;
    if allowed.iter().any(|r| r == &sess.role) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "forbidden").into_response())
    }
}

fn bearer(req: &Request) -> Option<String> {
    let value = req.headers().get("Authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(ToString::to_string)
}
