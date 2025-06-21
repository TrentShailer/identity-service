use core::time::Duration;

use api_helper::{ApiKey, ErrorResponse, Json, Jwt, Problem, ReportUnexpected};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiState, models::Identity, sql};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostIdentity {
    pub username: String,
}

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

pub async fn get_identity(
    State(state): State<ApiState>,
    ApiKey(_): ApiKey,
    Jwt(jwt): Jwt,
) -> Result<(StatusCode, Json<Identity>), ErrorResponse> {
    let connection = state
        .pool
        .get()
        .await
        .report_error("get database connection")
        .map_err(|_| ErrorResponse::server_error())?;

    let row = connection
        .query_one(sql::identities::get_by_id()[0], &[&jwt.claims.sub])
        .await
        .map_err(|_| ErrorResponse::not_found())?;

    let idenity = Identity::from_row(&row).ok_or_else(ErrorResponse::server_error)?;

    Ok((StatusCode::OK, Json(idenity)))
}

pub async fn get_identity_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ApiKey(_): ApiKey,
    Jwt(jwt): Jwt,
) -> Result<(StatusCode, Json<Identity>), ErrorResponse> {
    if id != jwt.claims.sub {
        return Err(ErrorResponse::not_found());
    }

    let connection = state
        .pool
        .get()
        .await
        .report_error("get database connection")
        .map_err(|_| ErrorResponse::server_error())?;

    let row = connection
        .query_one(sql::identities::get_by_id()[0], &[&id])
        .await
        .map_err(|_| ErrorResponse::not_found())?;

    let idenity = Identity::from_row(&row).ok_or_else(ErrorResponse::server_error)?;

    Ok((StatusCode::OK, Json(idenity)))
}

pub async fn delete_identity_by_id(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ApiKey(_): ApiKey,
    Jwt(jwt): Jwt,
) -> Result<StatusCode, ErrorResponse> {
    if id != jwt.claims.sub {
        return Err(ErrorResponse::not_found());
    }

    let connection = state
        .pool
        .get()
        .await
        .report_error("get database connection")
        .map_err(|_| ErrorResponse::server_error())?;

    connection
        .execute(sql::identities::delete_by_id()[0], &[&id])
        .await
        .map_err(|_| ErrorResponse::server_error())?;

    Ok(StatusCode::NO_CONTENT)
}
