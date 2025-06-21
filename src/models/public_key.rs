use api_helper::ReportUnexpected;
use postgres::Row;
use serde::{Deserialize, Serialize};
use sql_helper_lib::SqlTimestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    pub raw_id: String,
    pub identity_id: String,
    pub public_key: String,
    pub public_key_algorithm: i32,
    pub created: SqlTimestamp,
}

impl PublicKey {
    #[track_caller]
    pub fn from_row(row: &Row) -> Option<Self> {
        let raw_id: String = row
            .try_get("raw_id")
            .report_error("failed getting `raw_id`")
            .ok()?;

        let identity_id: String = row
            .try_get("identity_id")
            .report_error("failed getting `identity_id`")
            .ok()?;

        let public_key: String = row
            .try_get("public_key")
            .report_error("failed getting `public_key`")
            .ok()?;

        let public_key_algorithm: i32 = row
            .try_get("public_key_algorithm")
            .report_error("failed getting `public_key_algorithm`")
            .ok()?;

        let created: SqlTimestamp = row
            .try_get("created")
            .report_error("failed getting `created`")
            .ok()?;

        Some(Self {
            identity_id,
            raw_id,
            public_key,
            public_key_algorithm,
            created,
        })
    }
}
