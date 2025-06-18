use api_helper::{ApiKey, ErrorResponse, Json, Problem, ReportUnexpected};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiState, identity::Identity, sql};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostIdentity {
    pub username: String,
}
#[axum::debug_handler]
pub async fn post_identity(
    State(state): State<ApiState>,
    ApiKey(_): ApiKey,
    Json(body): Json<PostIdentity>,
) -> Result<(StatusCode, HeaderMap, Json<Identity>), ErrorResponse> {
    let PostIdentity { username } = body;

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
        if !problems.is_empty() {
            return Err(ErrorResponse::new(StatusCode::BAD_REQUEST, problems));
        }
    }

    // Reject if username exists
    {
        let connection = state.pool.get().await.unwrap();

        let username_conflict = connection
            .query_opt(sql::identities::get_by_username()[0], &[&username])
            .await
            .report_error("checking conflicting identity")
            .map_err(|_| ErrorResponse::server_error())?
            .is_some();

        if username_conflict {
            return Err(ErrorResponse::single(
                StatusCode::CONFLICT,
                Problem::new(
                    "username-confict",
                    "An identity with this username already exists",
                )
                .pointer("$.username"),
            ));
        }
    }

    // Create identity
    let identity = {
        let id = format!("ts-identity-{}", Uuid::new_v4());
        let display_name = format!("TS Identity {username}");

        let connection = state.pool.get().await.unwrap();

        let row = connection
            .query_one(
                sql::identities::create()[0],
                &[&id, &username, &display_name],
            )
            .await
            .report_error("creating identity")
            .map_err(|_| ErrorResponse::server_error())?;

        Identity::from_row(row).ok_or_else(ErrorResponse::server_error)?
    };

    // Create token
    let token = state
        .jwt_encoder
        .encode(identity.id.clone())
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
