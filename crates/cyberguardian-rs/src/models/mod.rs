use chrono::{DateTime, Utc};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub target: String,
    pub tool: String,
    pub profile: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Asset {
    pub hostname: Option<String>,
    pub ip: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AssetRecord {
    pub id: i64,
    pub ip: String,
    pub hostname: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Service {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub key: String,
    pub severity: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct FindingRecord {
    pub id: i64,
    pub key: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub finding_key: String,
    pub raw: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NormalizedScan {
    pub assets: Vec<Asset>,
    pub services: Vec<Service>,
    pub findings: Vec<Finding>,
    pub evidence: Vec<Evidence>,
}
