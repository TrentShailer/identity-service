use axum::extract::State;
use http::StatusCode;
use serde::Serialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse, Json, token::extractor::Token,
    webauthn::persisted_public_key::PersistedPublicKey,
};
use ts_sql_helper_lib::{FromRow, query};

use crate::ApiState;

query! {
    name: GetPublicKeys,
    query: r#"
        SELECT
            raw_id,
            identity_id,
            display_name,
            public_key,
            public_key_algorithm,
            transports,
            signature_counter,
            created,
            last_used
        FROM
            public_keys
        WHERE
            identity_id = $1::BYTEA
            "#
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub public_keys: Vec<PersistedPublicKey>,
}

pub async fn get_handler(
    _: ApiKey,
    Token(token): Token,
    State(ApiState { pool, .. }): State<ApiState>,
) -> Result<(StatusCode, Json<Response>), ErrorResponse> {
    let identity_id = token.claims.sub.decode_base64().unprocessable_entity()?;

    let database = pool.get().await.internal_server_error()?;
    let public_keys = database
        .query(
            GetPublicKeys::QUERY,
            GetPublicKeys::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error()?
        .into_iter()
        .map(|row| PersistedPublicKey::from_row(&row).unwrap())
        .collect::<Vec<_>>();

    Ok((StatusCode::OK, Json(Response { public_keys })))
}
