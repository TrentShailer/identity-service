use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse,
    token::{extractor::Token, json_web_token::TokenType},
};
use ts_sql_helper_lib::query;

use crate::{ApiState, routes::revoked_tokens::revoke_token};

query! {
    name: DeleteIdentity,
    query: r#"
        DELETE FROM
            identities
        WHERE
            id = $1::BYTEA"#
}

pub async fn delete_handler(
    _: ApiKey,
    Token(token): Token,
    State(ApiState { pool, .. }): State<ApiState>,
    Path(identity_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let expected_consent = TokenType::Consent {
        act: format!("DELETE /identities/{identity_id}"),
    };

    let database = pool.get().await.internal_server_error()?;
    revoke_token(&database, &token.claims.tid, token.claims.exp).await;

    if token.claims.typ != expected_consent {
        return Err(ErrorResponse::forbidden());
    }

    if token.claims.sub != identity_id {
        return Err(ErrorResponse::forbidden());
    }

    let identity_id = identity_id
        .decode_base64()
        .map_err(|_| ErrorResponse::unprocessable_entity())?;

    database
        .execute(
            DeleteIdentity::QUERY,
            DeleteIdentity::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error()?;

    Ok(StatusCode::NO_CONTENT)
}
