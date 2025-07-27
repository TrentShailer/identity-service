use axum::extract::State;
use http::StatusCode;

use ts_api_helper::{ApiKey, ErrorResponse, InlineErrorResponse, token::extractor::Token};

use crate::{ApiState, routes::revoked_tokens::revoke_token};

pub async fn post_handler(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let database = state.pool.get().await.internal_server_error()?;
    if !revoke_token(&database, &token.claims.tid, token.claims.exp).await {
        return Err(ErrorResponse::internal_server_error());
    };

    Ok(StatusCode::NO_CONTENT)
}
