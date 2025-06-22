use api_helper::InternalServerError;
use serde::{Deserialize, Serialize};
use sql_helper_lib::SqlTimestamp;
use tokio_postgres::Row;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub expires: Option<SqlTimestamp>,
    pub created: SqlTimestamp,
}

impl Identity {
    #[track_caller]
    pub fn from_row(row: &Row) -> Option<Self> {
        let id: String = row.try_get("id").internal_server_error_context("id").ok()?;

        let username: String = row
            .try_get("username")
            .internal_server_error_context("username")
            .ok()?;

        let display_name: String = row
            .try_get("display_name")
            .internal_server_error_context("display_name")
            .ok()?;

        let expires: Option<SqlTimestamp> = row
            .try_get("expires")
            .internal_server_error_context("expires")
            .ok()?;

        let created: SqlTimestamp = row
            .try_get("created")
            .internal_server_error_context("created")
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
