use api_helper::{ReportUnexpected, SqlTimestamp};
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub expires: Option<SqlTimestamp>,
    pub created: SqlTimestamp,
}

impl Identity {
    #[track_caller]
    pub fn from_row(row: Row) -> Option<Self> {
        let id: String = row.try_get("id").report_error("failed getting `id`").ok()?;

        let username: String = row
            .try_get("username")
            .report_error("failed getting `username`")
            .ok()?;

        let display_name: String = row
            .try_get("display_name")
            .report_error("failed getting `display_name`")
            .ok()?;

        let expires: Option<SqlTimestamp> = row
            .try_get("expires")
            .report_error("failed getting `expires`")
            .ok()?;

        let created: SqlTimestamp = row
            .try_get("created")
            .report_error("failed getting `created`")
            .ok()?;

        Some(Self {
            id,
            username,
            display_name,
            expires,
            created,
        })
    }
}
