use api_helper::ReportUnexpected;
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
            .report_error("failed getting `challenge`")
            .ok()?;

        let identity_id: Option<String> = row
            .try_get("identity_id")
            .report_error("failed getting `identity_id`")
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
            challenge,
            identity_id,
            created,
            expires,
        })
    }
}
