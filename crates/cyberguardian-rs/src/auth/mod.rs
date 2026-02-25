use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub role: Role,
}

#[derive(Clone, Default)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionStore {
    pub async fn login(&self, username: &str, password: &str) -> Option<(String, Role)> {
        let role = match (username, password) {
            ("admin", "admin123") => Role::Admin,
            ("operator", "operator123") => Role::Operator,
            ("viewer", "viewer123") => Role::Viewer,
            _ => return None,
        };
        let token = Uuid::new_v4().to_string();
        self.inner.write().await.insert(
            token.clone(),
            Session {
                username: username.to_string(),
                role: role.clone(),
            },
        );
        Some((token, role))
    }

    pub async fn get(&self, token: &str) -> Option<Session> {
        self.inner.read().await.get(token).cloned()
    }
}
