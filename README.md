# CyberGuardian-RS

Application Rust orientée audit de sécurité **autorisé** (réseau/web), remplaçant un ancien stack PHP+Java+MySQL.

## Stack
- `axum` + `tokio` pour API HTTP async
- `sqlx` + SQLite par défaut
- Queue jobs async (canal + worker)
- Parsing Nmap XML avec `quick-xml`
- Logs structurés via `tracing`

## Démarrage rapide

### Linux/macOS
```bash
cargo run -p cyberguardian-rs
```

### Windows (PowerShell)
```powershell
cargo run -p cyberguardian-rs
```

Le serveur écoute par défaut sur `http://127.0.0.1:8080`.

## Configuration
Créer `config.json` à la racine:

```json
{
  "host": "127.0.0.1",
  "port": 8080,
  "database_url": "sqlite://cyberguardian.db",
  "scope_allowlist": ["127.0.0.1/32", "localhost"],
  "profile_default_timeout_secs": 60,
  "feature_nuclei": false,
  "feature_zap": false,
  "feature_nikto": false,
  "feature_ffuf": false,
  "feature_amass": false
}
```

Variables d'environnement supportées:
- `CYBERGUARDIAN_CONFIG`
- `CG_HOST`
- `CG_PORT`
- `CG_DATABASE_URL`
- `CG_SCOPE_ALLOWLIST` (CSV)

## Endpoints
- `GET /api/health`
- `POST /api/auth/login`
- `GET /api/jobs` (RBAC viewer/operator/admin)
- `POST /api/jobs` (RBAC operator/admin)
- `GET /api/assets` (RBAC viewer/operator/admin)
- `GET /api/findings` (RBAC viewer/operator/admin)
- `GET /` (dashboard HTML avec login + tables jobs/assets/findings)

Comptes locaux de démonstration:
- `admin/admin123`
- `operator/operator123`
- `viewer/viewer123`

## Sécurité / Guardrails
- Scope obligatoire via allowlist IP/CIDR/domaines.
- Rate limiting simple sur la création de jobs.
- Audit log pour création de job et lancement d'outil.
- Exécution d'outils externes avec allowlist + timeout.
- Feature flags modules à risque désactivés par défaut.
- Aucun mode d'exploitation automatisée activé.

## Tests
```bash
cargo test -p cyberguardian-rs
```
