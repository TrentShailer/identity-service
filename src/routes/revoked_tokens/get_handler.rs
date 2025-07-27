use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{ApiKey, ErrorResponse, InlineErrorResponse};
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

pub async fn get_handler(
    _: ApiKey,
    Path(token): Path<String>,
    State(ApiState { pool, .. }): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let database = pool.get().await.internal_server_error()?;

    let row = database
        .query_opt(
            GetRevokedToken::QUERY,
            GetRevokedToken::params(&token).as_array().as_slice(),
        )
        .await
        .internal_server_error()?;

    if row.is_some() {
        Ok(StatusCode::OK)
    } else {
        Err(ErrorResponse {
            status: StatusCode::NOT_FOUND,
            problems: vec![],
        })
    }
}
