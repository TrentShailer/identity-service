use axum::{
    Router,
    routing::{delete, post},
};

use crate::ApiState;

use delete_handler::delete_handler;
use get_handler::get_handler;
use post_handler::post_handler;

mod delete_handler;
mod get_handler;
mod post_handler;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/public-keys", post(post_handler).get(get_handler))
        .route("/public-keys/{publicKeyId}", delete(delete_handler))
        .with_state(state)
}
