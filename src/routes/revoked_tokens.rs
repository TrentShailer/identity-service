use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{ApiKey, ErrorResponse, InternalServerError};
use ts_sql_helper_lib::query;

use crate::ApiState;

query! {
    name: GetRevokedToken,
    query: r#"
        SELECT
            token,
            expires
        FROM
            revocations
        WHERE
            token = $1::VARCHAR;"#
}

pub async fn get_revoked_token(
    ApiKey(_): ApiKey,
    Path(token): Path<String>,
    State(state): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let row = connection
        .query_opt(
            GetRevokedToken::QUERY,
            GetRevokedToken::params(&token).as_array().as_slice(),
        )
        .await
        .internal_server_error("get revocation by token")?;

    if row.is_some() {
        Ok(StatusCode::OK)
    } else {
        Err(ErrorResponse::not_found::<String>(None))
    }
}
