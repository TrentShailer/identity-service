use axum::{Router, routing::post};

use crate::ApiState;

use post_handler::post_handler;

mod post_handler;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/challenges", post(post_handler))
        .with_state(state)
}
