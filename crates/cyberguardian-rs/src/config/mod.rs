use std::{env, fs};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub scope_allowlist: Vec<String>,
    pub profile_default_timeout_secs: u64,
    pub feature_nuclei: bool,
    pub feature_zap: bool,
    pub feature_nikto: bool,
    pub feature_ffuf: bool,
    pub feature_amass: bool,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        let path = env::var("CYBERGUARDIAN_CONFIG").unwrap_or_else(|_| "config.json".to_string());
        let file_cfg: Option<AppConfig> = fs::read_to_string(&path)
            .ok()
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .context("failed to parse config.json")?;

        let mut cfg = file_cfg.unwrap_or_else(Self::default);

        if let Ok(v) = env::var("CG_HOST") {
            cfg.host = v;
        }
        if let Ok(v) = env::var("CG_PORT") {
            cfg.port = v.parse().unwrap_or(cfg.port);
        }
        if let Ok(v) = env::var("CG_DATABASE_URL") {
            cfg.database_url = v;
        }
        if let Ok(v) = env::var("CG_SCOPE_ALLOWLIST") {
            cfg.scope_allowlist = v.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(cfg)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            database_url: "sqlite://cyberguardian.db".to_string(),
            scope_allowlist: vec!["127.0.0.1/32".to_string(), "localhost".to_string()],
            profile_default_timeout_secs: 60,
            feature_nuclei: false,
            feature_zap: false,
            feature_nikto: false,
            feature_ffuf: false,
            feature_amass: false,
        }
    }
}
