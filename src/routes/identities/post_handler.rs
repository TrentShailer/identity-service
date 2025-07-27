use axum::extract::State;
use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use rand::RngCore;
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, EncodeBase64, ErrorResponse, InlineErrorResponse, Json, Problem,
    token::json_web_token::TokenType,
};
use ts_sql_helper_lib::{ParseFromRow, SqlError, query};

use crate::{ApiState, models::Identity};

query! {
    name: CreateIdentity,
    query: r#"
    INSERT INTO
        identities (id, username, display_name)
    VALUES
        ($1::BYTEA, $2::VARCHAR, $3::VARCHAR)
    RETURNING
        id,
        username,
        display_name,
        created,
        expires;"#
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostIdentitiesBody {
    username: String,
    display_name: String,
}

pub async fn post_handler(
    _: ApiKey,
    State(ApiState {
        pool, signing_jwk, ..
    }): State<ApiState>,
    Json(PostIdentitiesBody {
        username,
        display_name,
    }): Json<PostIdentitiesBody>,
) -> Result<(StatusCode, HeaderMap, Json<Identity>), ErrorResponse> {
    // Validate body
    {
        let mut problems: Vec<Problem> = vec![];

        // Validate username
        if username.chars().count() < 4 {
            problems.push(Problem::new(
                "/username",
                "must be at least four characters",
            ));
        }
        if username.chars().count() > 64 {
            problems.push(Problem::new("/username", "must be at most 64 characters"));
        }

        // Validate display name
        if display_name.chars().count() < 4 {
            problems.push(Problem::new(
                "/displayName",
                "name must be at least four characters",
            ));
        }
        if display_name.chars().count() > 64 {
            problems.push(Problem::new(
                "/displayName",
                "name must be at most 64 characters",
            ));
        }

        if !problems.is_empty() {
            return Err(ErrorResponse::bad_request(problems));
        }
    }

    let mut id = [0u8; 32];
    rand::rng().fill_bytes(&mut id);

    // Create identity
    let identity: Identity = {
        let database = pool.get().await.internal_server_error()?;

        database
            .query_one(
                CreateIdentity::QUERY,
                CreateIdentity::params(&id, &username, &display_name)
                    .as_array()
                    .as_slice(),
            )
            .await
            .unique_violation(|| {
                ErrorResponse::bad_request(vec![Problem::new(
                    "/username",
                    "an identity with this username already exists",
                )])
            })?
            .internal_server_error()?
            .parse()
            .unwrap()
    };

    let token = signing_jwk
        .issue(identity.id.encode_base64(), TokenType::Provisioning)
        .internal_server_error()?;
    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("bearer {}", token.serialize())).internal_server_error()?,
    );

    Ok((StatusCode::CREATED, headers, Json(identity)))
}
