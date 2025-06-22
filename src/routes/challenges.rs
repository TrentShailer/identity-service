use api_helper::{ApiKey, ErrorResponse, InternalServerError, Json, Jwt};
use axum::extract::State;
use base64::{Engine, prelude::BASE64_STANDARD};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sql_helper_lib::SqlError;

use crate::{ApiState, models::Challenge, sql};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostChallengesBody {
    pub identity_id: Option<String>,
}

pub async fn post_challenges(
    State(state): State<ApiState>,
    ApiKey(_): ApiKey,
    jwt: Option<Jwt>,
    body: Option<Json<PostChallengesBody>>,
) -> Result<(StatusCode, Json<Challenge>), ErrorResponse> {
    let identity_id: Option<String> = {
        if let Some(body) = body {
            if let Some(id) = body.0.identity_id {
                if let Some(jwt) = jwt {
                    if jwt.0.claims.sub == id {
                        Some(id)
                    } else {
                        return Err(ErrorResponse::not_found(Some("$.identity_id")));
                    }
                } else {
                    return Err(ErrorResponse::unauthenticated());
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let challenge = {
        let mut challenge = vec![0u8; 32];
        rand::rng().fill(&mut challenge[..]);
        BASE64_STANDARD.encode(challenge)
    };

    let connection = state.pool.get().await.internal_server_error()?;

    let challenge = {
        let row = connection
            .query_one(
                sql::challenge::create()[0],
                sql::challenge::CreateParams {
                    p1: &challenge,
                    p2: identity_id.as_deref(),
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .fk_violation(ErrorResponse::unauthenticated)?
            .internal_server_error()?;

        Challenge::from_row(&row).internal_server_error()?
    };

    Ok((StatusCode::CREATED, Json(challenge)))
}
