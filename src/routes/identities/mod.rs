use axum::{
    Router,
    routing::{get, post},
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
        .route("/identities", post(post_handler))
        .route(
            "/identities/{identityId}",
            get(get_handler).delete(delete_handler),
        )
        .with_state(state)
}
