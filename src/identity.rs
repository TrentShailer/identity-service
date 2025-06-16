use api_helper::ReportUnexpected;
use jiff::Zoned;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub expiry: Option<Zoned>,
    pub created: Zoned,
}

impl Identity {
    #[track_caller]
    pub fn maybe_from_row(row: Row) -> Option<Self> {
        let id: String = row.try_get("id").report_error("failed getting `id`").ok()?;

        let username: String = row
            .try_get("username")
            .report_error("failed getting `username`")
            .ok()?;

        let display_name: String = row
            .try_get("display_name")
            .report_error("failed getting `display_name`")
            .ok()?;

        let expiry_string: Option<String> = row
            .try_get("expiry")
            .report_error("failed getting `expiry`")
            .ok()?;

        let created_string: String = row
            .try_get("created")
            .report_error("failed getting `created`")
            .ok()?;

        let expiry = expiry_string.and_then(|value| {
            value
                .parse::<Zoned>()
                .report_error("failed parsing `expiry`")
                .ok()
        });

        let created = created_string
            .parse::<Zoned>()
            .report_error("failed parsing `created`")
            .ok()?;

        Some(Self {
            id,
            username,
            display_name,
            expiry,
            created,
        })
    }
}
