mod post_handler;

use axum::{Router, routing::post};
use post_handler::post_handler;

use crate::ApiState;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/tokens", post(post_handler))
        .with_state(state)
}
