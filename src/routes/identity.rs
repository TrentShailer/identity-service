use api_helper::{ConnectionPool, ErrorResponse, Json, Problem, ReportUnexpected};
use axum::{extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{identity::Identity, sql};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostIdentity {
    pub username: String,
}

pub async fn post_identity(
    State(pool): State<ConnectionPool>,
    Json(body): Json<PostIdentity>,
) -> Result<(StatusCode, Json<Identity>), ErrorResponse> {
    let PostIdentity { username } = body;

    let mut problems: Vec<Problem> = vec![];

    // Validate username
    {
        if username.is_empty() {
            problems.push(Problem::invalid_field(
                "The username must not be empty",
                "$.username",
            ));
        }
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
        let connection = pool.get().await.unwrap();

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

        let connection = pool.get().await.unwrap();

        connection
            .query_one(
                sql::identities::create()[0],
                &[&id, &username, &display_name],
            )
            .await
            .report_error("creating identity")
            .map_err(|_| ErrorResponse::server_error())?
    };

    let identity = Identity::maybe_from_row(identity).ok_or_else(ErrorResponse::server_error)?;

    Ok((StatusCode::CREATED, Json(identity)))
}
