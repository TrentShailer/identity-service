use api_helper::ReportUnexpected;
use postgres::Row;
use serde::{Deserialize, Serialize};
use sql_helper_lib::SqlTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub id: String,
    pub identity_id: String,
    pub challenge: Vec<u8>,
    pub created: SqlTimestamp,
    pub expires: SqlTimestamp,
}

impl Challenge {
    #[track_caller]
    pub fn from_row(row: &Row) -> Option<Self> {
        let id: String = row.try_get("id").report_error("failed getting `id`").ok()?;

        let identity_id: String = row
            .try_get("identity_id")
            .report_error("failed getting `identity_id`")
            .ok()?;

        let challenge: Vec<u8> = row
            .try_get("challenge")
            .report_error("failed getting `challenge`")
            .ok()?;

        let created: SqlTimestamp = row
            .try_get("created")
            .report_error("failed getting `created`")
            .ok()?;

        let expires: SqlTimestamp = row
            .try_get("expires")
            .report_error("failed getting `expires`")
            .ok()?;

        Some(Self {
            id,
            identity_id,
            challenge,
            created,
            expires,
        })
    }
}
