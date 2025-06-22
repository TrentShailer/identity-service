use core::time::Duration;

use api_helper::{ApiKey, ErrorResponse, Json, Problem, ReportUnexpected};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use rand::Rng;
use reqwest::StatusCode;
use serde::Deserialize;
use sql_helper_lib::SqlError;

use crate::{
    ApiState,
    models::{IDENTITY_FLAG, Identity},
    sql,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostIdentities {
    pub username: String,
    pub display_name: String,
}

pub async fn post_identities(
    State(state): State<ApiState>,
    _: ApiKey,
    Json(body): Json<PostIdentities>,
) -> Result<(StatusCode, HeaderMap, Json<Identity>), ErrorResponse> {
    let PostIdentities {
        username,
        display_name,
    } = body;

    // Validate body
    {
        let mut problems: Vec<Problem> = vec![];

        // Validate username
        {
            if username.chars().count() < 4 {
                problems.push(Problem::invalid_field(
                    "The username must be at least four characters.",
                    "$.username",
                ));
            }
            if username.chars().count() > 64 {
                problems.push(Problem::invalid_field(
                    "The username must be at most 64 characters.",
                    "$.username",
                ));
            }
        }
        // Validate display name
        {
            if display_name.chars().count() < 4 {
                problems.push(Problem::invalid_field(
                    "The display name must be at least four characters.",
                    "$.displayName",
                ));
            }
            if display_name.chars().count() > 64 {
                problems.push(Problem::invalid_field(
                    "The display name must be at most 64 characters.",
                    "$.displayName",
                ));
            }
        }

        if !problems.is_empty() {
            return Err(ErrorResponse::new(StatusCode::BAD_REQUEST, problems));
        }
    }

    // Create identity
    let identity = {
        let mut id = [0u8; 32];
        id[0] = IDENTITY_FLAG;
        rand::rng().fill(&mut id[1..]);
        let id = BASE64_STANDARD.encode(id);

        let connection = state
            .pool
            .get()
            .await
            .report_error("get database connection")
            .map_err(|_| ErrorResponse::server_error())?;

        let row = connection
            .query_one(
                sql::identities::create()[0],
                &[&id, &username, &display_name],
            )
            .await
            .unique_violation(|| {
                ErrorResponse::single(
                    StatusCode::CONFLICT,
                    Problem::new(
                        "username-confict",
                        "An identity with this username already exists",
                    )
                    .pointer("$.username"),
                )
            })?
            .report_error("creating identity")
            .map_err(|_| ErrorResponse::server_error())?;

        Identity::from_row(&row).ok_or_else(ErrorResponse::server_error)?
    };

    // Create token
    let token = state
        .jwt_encoder
        .encode(identity.id.clone(), Some(Duration::from_secs(60 * 60 * 4)))
        .report_error("encoding token")
        .map_err(|_| ErrorResponse::server_error())?;

    let mut headers = HeaderMap::new();
    headers.append(
        "Authorization",
        HeaderValue::from_str(&format!("bearer {token}"))
            .report_error("creating header value")
            .map_err(|_| ErrorResponse::server_error())?,
    );

    Ok((StatusCode::CREATED, headers, Json(identity)))
}
