use serde::{Deserialize, Serialize};
use ts_sql_helper_lib::{FromRow, SqlTimestamp};

#[derive(Clone, Debug, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(with = "ts_api_helper::serde_base64")]
    pub id: Vec<u8>,
    pub username: String,
    pub display_name: String,
    pub expires: Option<SqlTimestamp>,
    pub created: SqlTimestamp,
}
