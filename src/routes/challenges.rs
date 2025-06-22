use api_helper::{ApiKey, ErrorResponse, Json, Jwt, ReportUnexpected};
use axum::{debug_handler, extract::State};
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
                        return Err(ErrorResponse::not_found());
                    }
                } else {
                    return Err(ErrorResponse::unuathenticated());
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

    let connection = state
        .pool
        .get()
        .await
        .report_error("get database connection")
        .map_err(|_| ErrorResponse::server_error())?;

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
            .fk_violation(ErrorResponse::unuathenticated)?
            .report_error("insert challenge")
            .map_err(|_| ErrorResponse::server_error())?;

        Challenge::from_row(&row).ok_or_else(ErrorResponse::server_error)?
    };

    Ok((StatusCode::CREATED, Json(challenge)))
}
