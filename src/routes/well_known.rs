use axum::extract::State;
use http::StatusCode;
use ts_api_helper::{ErrorResponse, Json, token::json_web_key::JsonWebKeySet};

use crate::ApiState;

pub async fn get_well_known_jwks(
    State(state): State<ApiState>,
) -> Result<(StatusCode, Json<JsonWebKeySet>), ErrorResponse> {
    Ok((StatusCode::OK, Json(state.jwks_file)))
}
