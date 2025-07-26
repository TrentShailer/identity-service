use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use http::{StatusCode, header::AUTHORIZATION};
use rand::Rng;
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, EncodeBase64, ErrorResponse, InternalServerError, Json, Problem,
    token::{extractor::Token, json_web_token::TokenType},
};
use ts_sql_helper_lib::{FromRow, SqlError, query};

use crate::{ApiState, models::Identity, routes::revoke_token};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostIdentities {
    pub username: String,
    pub display_name: String,
}

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
                CreateIdentity::QUERY,
                CreateIdentity::params(&id, &username, &display_name)
                    .as_array()
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

query! {
    name: GetIdentity,
    query: r#"
    SELECT
        id,
        username,
        display_name,
        created,
        expires
    FROM
        identities
    WHERE
        id = $1::BYTEA;"#
}

pub async fn get_identity(
    State(state): State<ApiState>,
    _: ApiKey,
    Token(token): Token,
    Path(identity_id): Path<String>,
) -> Result<(StatusCode, Json<Identity>), ErrorResponse> {
    if token.claims.typ != TokenType::Common {
        return Err(ErrorResponse::unauthenticated());
    }

    if identity_id != token.claims.sub {
        return Err(ErrorResponse::not_found(Some("/identityId")));
    }

    let identity_id =
        Base64UrlUnpadded::decode_vec(&identity_id).internal_server_error("decode identity ID")?;

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get pool connection")?;
    let row = connection
        .query_opt(
            GetIdentity::QUERY,
            GetIdentity::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error("query identity")?
        .ok_or_else(|| ErrorResponse::not_found(Some("/identityId")))?;
    let identity = Identity::from_row(&row).internal_server_error("convert row to identity")?;

    Ok((StatusCode::OK, Json(identity)))
}

query! {
    name: DeleteIdentity,
    query: r#"
        DELETE FROM
            identities
        WHERE
            id = $1::BYTEA"#
}

pub async fn delete_identity(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
    Path(identity_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let expected_consent = TokenType::Consent {
        act: format!("DELETE /identities/{identity_id}"),
    };
    if token.claims.typ != expected_consent {
        return Err(ErrorResponse::unauthenticated());
    }

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get pool connection")?;

    revoke_token(&connection, &token.claims.tid, token.claims.exp).await;

    if token.claims.sub != identity_id {
        return Err(ErrorResponse::unauthenticated());
    }

    let identity_id = identity_id
        .decode_base64()
        .map_err(|_| ErrorResponse::bad_request(vec![Problem::pointer("/identityId")]))?;

    connection
        .execute(
            DeleteIdentity::QUERY,
            DeleteIdentity::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error("delete identity")?;

    Ok(StatusCode::NO_CONTENT)
}
