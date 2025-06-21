use api_helper::{ErrorResponse, Json};
use axum::extract::State;
use jsonwebtoken::jwk::JwkSet;
use reqwest::StatusCode;

use crate::ApiState;

pub async fn get_jwks(
    State(state): State<ApiState>,
) -> Result<(StatusCode, Json<JwkSet>), ErrorResponse> {
    Ok((StatusCode::OK, Json(state.jwks_file)))
}
