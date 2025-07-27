use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse,
    token::{extractor::Token, json_web_token::TokenType},
};
use ts_sql_helper_lib::query;

use crate::{ApiState, routes::revoked_tokens::revoke_token};

query! {
    name: GetPublicKeyCount,
    query: r#"
        SELECT
            COUNT(raw_id) as public_key_count
        FROM
            public_keys
        WHERE
            identity_id = $1::BYTEA"#
}

query! {
    name: DeletePublicKey,
    query: r#"
        DELETE FROM
            public_keys
        WHERE
            raw_id = $1::BYTEA
            AND identity_id = $2::BYTEA"#
}

pub async fn delete_handler(
    _: ApiKey,
    Token(token): Token,
    State(ApiState { pool, .. }): State<ApiState>,
    Path(public_key_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let expected_consent = TokenType::Consent {
        act: format!("DELETE /public-keys/{public_key_id}"),
    };
    if token.claims.typ != expected_consent {
        return Err(ErrorResponse::unauthenticated());
    }

    let database = pool.get().await.internal_server_error()?;
    revoke_token(&database, &token.claims.tid, token.claims.exp).await;

    let identity_id = token.claims.sub.decode_base64().unprocessable_entity()?;
    let public_key_id = public_key_id.decode_base64().unprocessable_entity()?;

    // Ensure identity always has one public key
    {
        let public_key_count: i64 = database
            .query_one(
                GetPublicKeyCount::QUERY,
                GetPublicKeyCount::params(&identity_id)
                    .as_array()
                    .as_slice(),
            )
            .await
            .internal_server_error()?
            .try_get("public_key_count")
            .unwrap();
        if public_key_count == 0 {
            return Err(ErrorResponse::unauthenticated());
        }
        if public_key_count == 1 {
            return Err(ErrorResponse {
                status: StatusCode::NOT_ACCEPTABLE,
                problems: vec![],
            });
        }
    }

    database
        .execute(
            DeletePublicKey::QUERY,
            DeletePublicKey::params(&public_key_id, &identity_id)
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error()?;

    Ok(StatusCode::NO_CONTENT)
}
