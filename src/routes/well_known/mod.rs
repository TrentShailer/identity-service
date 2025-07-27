use axum::{Router, extract::State, routing::get};
use serde::Serialize;
use ts_api_helper::{
    Json,
    token::json_web_key::JsonWebKeySet,
    webauthn::public_key_credential_creation_options::{PublicKeyParameters, RelyingParty},
};

use crate::ApiState;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/.well-known/jwks.json", get(get_jwks))
        .route("/.well-known/relying-party.json", get(get_relying_party))
        .route(
            "/.well-known/public-key-parameters.json",
            get(get_public_key_parameters),
        )
        .with_state(state)
}

async fn get_jwks(State(ApiState { jwks_file, .. }): State<ApiState>) -> Json<JsonWebKeySet> {
    Json(jwks_file)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyParametersResponse {
    public_key_parameters: Vec<PublicKeyParameters>,
}

async fn get_public_key_parameters() -> Json<PublicKeyParametersResponse> {
    Json(PublicKeyParametersResponse {
        public_key_parameters: PublicKeyParameters::ALL.to_vec(),
    })
}

async fn get_relying_party(
    State(ApiState { relying_party, .. }): State<ApiState>,
) -> Json<RelyingParty> {
    Json(relying_party)
}
