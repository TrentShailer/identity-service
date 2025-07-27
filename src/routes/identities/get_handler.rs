use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse, Json, token::extractor::Token,
};
use ts_sql_helper_lib::{ParseFromRow, query};

use crate::{ApiState, models::Identity};

query! {
    name: GetIdentity,
    query: r#"
    SELECT
        id,
        username,
        display_name,
        created,
        expires
    FROM
        identities
    WHERE
        id = $1::BYTEA;"#
}

pub async fn get_handler(
    _: ApiKey,
    State(ApiState { pool, .. }): State<ApiState>,
    Token(token): Token,
    Path(identity_id): Path<String>,
) -> Result<(StatusCode, Json<Identity>), ErrorResponse> {
    if identity_id != token.claims.sub {
        return Err(ErrorResponse::forbidden());
    }

    let identity_id = identity_id.decode_base64().unprocessable_entity()?;

    let database = pool.get().await.internal_server_error()?;
    let identity = database
        .query_opt(
            GetIdentity::QUERY,
            GetIdentity::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error()?
        .ok_or_else(ErrorResponse::forbidden)?
        .parse()
        .unwrap();

    Ok((StatusCode::OK, Json(identity)))
}
