use sqlx::{migrate::Migrator, SqlitePool};

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn create_pool(url: &str) -> anyhow::Result<SqlitePool> {
    Ok(SqlitePool::connect(url).await?)
}

pub async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}
