use axum::{
    Router,
    extract::{Query, State},
    routing::get,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse, Json,
    webauthn::{
        public_key_credential::{Transports, Type},
        public_key_credential_request_options::AllowCredentials,
    },
};
use ts_sql_helper_lib::{FromRow, query};

use crate::ApiState;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/existing-credentials", get(handler))
        .with_state(state)
}

query! {
    name: GetCredentials,
    row: {raw_id: Vec<u8>, transports: Vec<Transports>},
    optional_params: [1, 2],
    query: r#"
        SELECT
            raw_id,
            transports
        FROM
            public_keys
        INNER JOIN
            identities
        ON
            identities.id = public_keys.identity_id
        WHERE
            CASE
                WHEN
                    $1::VARCHAR IS NOT NULL
                THEN
                    identities.username = $1::VARCHAR
                ELSE
                    true
            END
        AND
            CASE
                WHEN
                    $2::BYTEA IS NOT NULL
                THEN
                    public_keys.identity_id = $2::BYTEA
                ELSE
                    true
            END
            "#
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub credentials: Vec<AllowCredentials>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestQuery {
    username: Option<String>,
    identity_id: Option<String>,
}

pub async fn handler(
    _: ApiKey,
    State(ApiState { pool, .. }): State<ApiState>,
    Query(RequestQuery {
        username,
        identity_id,
    }): Query<RequestQuery>,
) -> Result<(StatusCode, Json<Response>), ErrorResponse> {
    let database = pool.get().await.internal_server_error()?;

    if identity_id.is_none() && username.is_none() {
        return Ok((
            StatusCode::OK,
            Json(Response {
                credentials: vec![],
            }),
        ));
    }

    let identity_id = if let Some(identity_id) = identity_id {
        Some(identity_id.decode_base64().unprocessable_entity()?)
    } else {
        None
    };

    let credentials = database
        .query(
            GetCredentials::QUERY,
            GetCredentials::params(username.as_deref(), identity_id.as_deref())
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error()?
        .into_iter()
        .map(|row| GetCredentialsRow::from_row(&row).unwrap())
        .map(|credential| AllowCredentials {
            id: credential.raw_id,
            transports: credential.transports,
            r#type: Type::PublicKey,
        })
        .collect();

    Ok((StatusCode::OK, Json(Response { credentials })))
}
