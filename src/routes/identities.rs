use core::marker::PhantomData;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use http::{StatusCode, header::AUTHORIZATION};
use rand::Rng;
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, EncodeBase64, ErrorResponse, InternalServerError, Json, Problem,
    token::json_web_token::TokenType,
};
use ts_sql_helper_lib::{FromRow, SqlError};

use crate::{ApiState, models::Identity, sql};

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
                    "/username",
                    "The username must be at least four characters.",
                ));
            }
            if username.chars().count() > 64 {
                problems.push(Problem::new(
                    "/username",
                    "The username must be at most 64 characters.",
                ));
            }
        }
        // Validate display name
        {
            if display_name.chars().count() < 4 {
                problems.push(Problem::new(
                    "/displayName",
                    "The display name must be at least four characters.",
                ));
            }
            if display_name.chars().count() > 64 {
                problems.push(Problem::new(
                    "/displayName",
                    "The display name must be at most 64 characters.",
                ));
            }
        }

        if !problems.is_empty() {
            return Err(ErrorResponse::bad_request(problems));
        }
    }

    let mut id = [0u8; 32];
    rand::rng().fill(&mut id[1..]);

    // Create identity
    let identity = {
        let connection = state
            .pool
            .get()
            .await
            .internal_server_error("get db connection")?;

        let row = connection
            .query_one(
                sql::identities::create()[0],
                sql::identities::CreateParams {
                    p1: &id,
                    p2: &username,
                    p3: &display_name,
                    phantom_data: PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .unique_violation(|| ErrorResponse {
                status: StatusCode::CONFLICT,
                problems: vec![Problem::new(
                    "/username",
                    "An identity with this username already exists.",
                )],
            })?
            .internal_server_error("execute create identity")?;

        Identity::from_row(&row).internal_server_error("convert row to identity")?
    };

    // Create token
    let (token, signature) = state
        .signing_jwk
        .issue(id.encode_base64(), TokenType::Provisioning)
        .internal_server_error("issue token")?;

    let header = token
        .header
        .encode()
        .internal_server_error("encode header")?;
    let claims = token
        .claims
        .encode()
        .internal_server_error("encode claims")?;

    let mut headers = HeaderMap::new();
    headers.append(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("bearer {header}.{claims}.{signature}"))
            .internal_server_error("convert token to header value")?,
    );

    Ok((StatusCode::CREATED, headers, Json(identity)))
}
