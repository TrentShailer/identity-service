use axum::{
    Router,
    routing::{get, post},
};
use get_handler::get_handler;
use jiff::Timestamp;
use post_handler::post_handler;
use tokio_postgres::Client;
use ts_rust_helper::error::ErrorLogger;
use ts_sql_helper_lib::{SqlTimestamp, query};

use crate::ApiState;

mod get_handler;
mod post_handler;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/revoked-tokens", post(post_handler))
        .route("/revoked-tokens/{tokenId}", get(get_handler))
        .with_state(state)
}

query! {
    name: RevokeToken,
    query: r#"
        INSERT INTO
            revocations (token, expires)
        VALUES
            ($1::VARCHAR, $2::TIMESTAMPTZ);"#
}

pub async fn revoke_token(client: &Client, token_id: &str, expiry: Timestamp) -> bool {
    client
        .execute(
            RevokeToken::QUERY,
            RevokeToken::params(token_id, &SqlTimestamp(expiry))
                .as_array()
                .as_slice(),
        )
        .await
        .log_error()
        .is_ok()
}
