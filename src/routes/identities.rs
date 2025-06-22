use core::time::Duration;

use api_helper::{ApiKey, ErrorResponse, InternalServerError, Json, Problem};
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
                problems.push(Problem::new(
                    "$.username",
                    "The username must be at least four characters.",
                ));
            }
            if username.chars().count() > 64 {
                problems.push(Problem::new(
                    "$.username",
                    "The username must be at most 64 characters.",
                ));
            }
        }
        // Validate display name
        {
            if display_name.chars().count() < 4 {
                problems.push(Problem::new(
                    "$.displayName",
                    "The display name must be at least four characters.",
                ));
            }
            if display_name.chars().count() > 64 {
                problems.push(Problem::new(
                    "$.displayName",
                    "The display name must be at most 64 characters.",
                ));
            }
        }

        if !problems.is_empty() {
            return Err(ErrorResponse::bad_request(problems));
        }
    }

    // Create identity
    let identity = {
        let mut id = [0u8; 32];
        id[0] = IDENTITY_FLAG;
        rand::rng().fill(&mut id[1..]);
        let id = BASE64_STANDARD.encode(id);

        let connection = state.pool.get().await.internal_server_error()?;

        let row = connection
            .query_one(
                sql::identities::create()[0],
                &[&id, &username, &display_name],
            )
            .await
            .unique_violation(|| ErrorResponse {
                status: StatusCode::CONFLICT,
                problems: vec![Problem::new(
                    "$.username",
                    "An identity with this username already exists.",
                )],
            })?
            .internal_server_error()?;

        Identity::from_row(&row).internal_server_error()?
    };

    // Create token
    let token = state
        .jwt_encoder
        .encode(identity.id.clone(), Some(Duration::from_secs(60 * 60 * 4)))
        .internal_server_error()?;

    let mut headers = HeaderMap::new();
    headers.append(
        "Authorization",
        HeaderValue::from_str(&format!("bearer {token}")).internal_server_error()?,
    );

    Ok((StatusCode::CREATED, headers, Json(identity)))
}
