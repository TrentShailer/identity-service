use axum::extract::State;
use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, EncodeBase64, ErrorResponse, InlineErrorResponse, Json, Problem,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::{
        public_key_credential::{PublicKeyCredential, Response},
        verification::VerificationResult,
    },
};
use ts_sql_helper_lib::query;

use crate::ApiState;

#[derive(Deserialize)]
pub struct Body {
    pub credential: PublicKeyCredential,
    #[serde(flatten)]
    pub typ: TokenType,
}

query! {
    name: UpdatePasskeyOnLogin,
    query: r#"
        UPDATE
            public_keys
        SET
            last_used = (timezone('utc', NOW())),
            signature_counter = $1::INT8
        WHERE
            raw_id = $2::BYTEA;"#
}

pub async fn post_handler(
    _: ApiKey,
    token: Option<Token>,
    State(state): State<ApiState>,
    Json(Body { credential, typ }): Json<Body>,
) -> Result<(StatusCode, HeaderMap), ErrorResponse> {
    let Response::AssertionResponse(assertion_response) = &credential.response else {
        return Err(ErrorResponse::unprocessable_entity());
    };

    match typ {
        TokenType::Common | TokenType::Consent { .. } => {}
        _ => {
            return Err(ErrorResponse::bad_request(vec![Problem::new(
                "/typ",
                "only common and consent tokens may be issued through this route",
            )]));
        }
    }

    let identity_id = match token.as_ref() {
        Some(Token(token)) => Some(token.claims.sub.decode_base64().unprocessable_entity()?),
        None => None,
    };

    let verification_result = credential
        .verify(&state, identity_id.as_deref())
        .await
        .internal_server_error()?;

    let VerificationResult::Valid { identity_id } = verification_result else {
        return Err(ErrorResponse::unauthenticated());
    };

    {
        let database = state.pool.get().await.internal_server_error()?;
        database
            .execute(
                UpdatePasskeyOnLogin::QUERY,
                UpdatePasskeyOnLogin::params(
                    &assertion_response
                        .authenticator_data
                        .signature_counter
                        .into(),
                    &credential.raw_id,
                )
                .as_array()
                .as_slice(),
            )
            .await
            .internal_server_error()?;
    }

    let mut header_map = HeaderMap::new();
    let token = state
        .signing_jwk
        .issue(identity_id.encode_base64(), typ)
        .internal_server_error()?;

    let value =
        HeaderValue::from_str(&format!("bearer {}", token.serialize())).internal_server_error()?;

    header_map.insert(AUTHORIZATION, value);

    Ok((StatusCode::CREATED, header_map))
}
