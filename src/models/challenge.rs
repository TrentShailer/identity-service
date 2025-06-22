use api_helper::InternalServerError;
use postgres::Row;
use serde::{Deserialize, Serialize};
use sql_helper_lib::SqlTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge: String,
    pub identity_id: Option<String>,
    pub created: SqlTimestamp,
    pub expires: SqlTimestamp,
}

impl Challenge {
    #[track_caller]
    pub fn from_row(row: &Row) -> Option<Self> {
        let challenge: String = row
            .try_get("challenge")
            .internal_server_error_context("challenge")
            .ok()?;

        let identity_id: Option<String> = row
            .try_get("identity_id")
            .internal_server_error_context("identity_id")
            .ok()?;

        let created: SqlTimestamp = row
            .try_get("created")
            .internal_server_error_context("created")
            .ok()?;

        let expires: SqlTimestamp = row
            .try_get("expires")
            .internal_server_error_context("expires")
            .ok()?;

        Some(Self {
            challenge,
            identity_id,
            created,
            expires,
        })
    }
}
