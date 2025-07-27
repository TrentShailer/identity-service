use axum::extract::State;
use http::{
    StatusCode,
    header::{HeaderMap, ORIGIN},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse, Json, token::extractor::Token,
    webauthn::challenge::Challenge,
};
use ts_sql_helper_lib::{ParseFromRow, SqlError, query};

use crate::ApiState;

query! {
    name: CreateChallenge,
    optional_params: [2],
    query: r#"
        INSERT INTO
            challenges (challenge, identity_id, origin)
        VALUES
            ($1::BYTEA, $2::BYTEA, $3::VARCHAR)
        RETURNING
            challenge,
            identity_id,
            origin,
            issued,
            expires;"#
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostBody {
    pub identity_id: Option<String>,
}

pub async fn post_handler(
    State(state): State<ApiState>,
    ApiKey(_): ApiKey,
    token: Option<Token>,
    headers: HeaderMap,
    body: Option<Json<PostBody>>,
) -> Result<(StatusCode, Json<Challenge>), ErrorResponse> {
    let origin = headers
        .get(ORIGIN)
        .unprocessable_entity()?
        .to_str()
        .unprocessable_entity()?;

    let identity_id = {
        if let Some(Json(body)) = body
            && let Some(identity_id) = body.identity_id
        {
            let Token(token) = token.unauthenticated()?;
            if token.claims.sub == identity_id {
                Some(identity_id.decode_base64().unprocessable_entity()?)
            } else {
                return Err(ErrorResponse::forbidden());
            }
        } else {
            None
        }
    };

    let challenge = {
        let database = state.pool.get().await.internal_server_error()?;

        let mut challenge = [0u8; 32];
        rand::rng().fill_bytes(&mut challenge);

        database
            .query_one(
                CreateChallenge::QUERY,
                CreateChallenge::params(&challenge, identity_id.as_deref(), origin)
                    .as_array()
                    .as_slice(),
            )
            .await
            .fk_violation(|| ErrorResponse::unauthenticated())?
            .internal_server_error()?
            .parse()
            .unwrap()
    };

    Ok((StatusCode::CREATED, Json(challenge)))
}
