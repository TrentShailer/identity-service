use core::marker::PhantomData;

use axum::extract::State;
use http::{
    StatusCode,
    header::{HeaderMap, ORIGIN},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InternalServerError, Json, token::extractor::Token,
    webauthn::challenge::Challenge,
};
use ts_sql_helper_lib::{FromRow, SqlError};

use crate::{ApiState, sql};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostChallengesBody {
    pub identity_id: Option<String>,
}

pub async fn post_challenges(
    State(state): State<ApiState>,
    ApiKey(_): ApiKey,
    token: Option<Token>,
    headers: HeaderMap,
    body: Option<Json<PostChallengesBody>>,
) -> Result<(StatusCode, Json<Challenge>), ErrorResponse> {
    let host = headers
        .get(ORIGIN)
        .ok_or_else(|| ErrorResponse::bad_request(vec![]))?
        .to_str()
        .map_err(|_| ErrorResponse::bad_request(vec![]))?;

    // TODO this sucks
    let identity_id: Option<Vec<u8>> = {
        if let Some(body) = body
            && let Some(id) = body.0.identity_id
        {
            if let Some(jwt) = token {
                if jwt.0.claims.sub == id {
                    Some(id.decode_base64().internal_server_error("decode id")?)
                } else {
                    return Err(ErrorResponse::not_found(Some("/identity_id")));
                }
            } else {
                return Err(ErrorResponse::unauthenticated());
            }
        } else {
            None
        }
    };

    let mut challenge = vec![0u8; 32];
    rand::rng().fill(&mut challenge[..]);

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let challenge = {
        let row = connection
            .query_one(
                sql::challenge::create()[0],
                sql::challenge::CreateParams {
                    p1: &challenge,
                    p2: identity_id.as_deref(),
                    p3: host,
                    phantom_data: PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .fk_violation(ErrorResponse::unauthenticated)?
            .internal_server_error("execute challenge create")?;

        Challenge::from_row(&row).internal_server_error("convert row to challenge")?
    };

    Ok((StatusCode::CREATED, Json(challenge)))
}
