use axum::extract::State;
use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InlineErrorResponse, Json, Problem,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::{
        persisted_public_key::PersistedPublicKey,
        public_key_credential::{PublicKeyCredential, Response},
        verification::VerificationResult,
    },
};
use ts_sql_helper_lib::{ParseFromRow, SqlError, query};

use crate::ApiState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Body {
    credential: PublicKeyCredential,
    display_name: String,
}

query! {
    name: CreatePublicKey,
    query: r#"
        INSERT INTO
        public_keys (
            raw_id,
            identity_id,
            display_name,
            public_key,
            public_key_algorithm,
            transports,
            signature_counter
        )
        VALUES (
            $1::BYTEA,
            $2::BYTEA,
            $3::VARCHAR,
            $4::BYTEA,
            $5::INT4,
            $6::VARCHAR[],
            $7::INT8
        )
        RETURNING
            raw_id,
            identity_id,
            display_name,
            public_key,
            public_key_algorithm,
            transports,
            signature_counter,
            created,
            last_used;"#
}

pub async fn post_handler(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
    Json(Body {
        credential,
        display_name,
    }): Json<Body>,
) -> Result<(StatusCode, HeaderMap, Json<PersistedPublicKey>), ErrorResponse> {
    if display_name.is_empty() {
        return Err(ErrorResponse::bad_request(vec![Problem::new(
            "/displayName",
            "must not be empty",
        )]));
    }

    let response = match credential.response {
        Response::AttestationResponse(ref response) => response,
        _ => return Err(ErrorResponse::unprocessable_entity()),
    };

    let identity_id = token.claims.sub.decode_base64().unprocessable_entity()?;
    let verification_result = credential
        .verify(&state, Some(&identity_id))
        .await
        .internal_server_error()?;

    let VerificationResult::Valid { identity_id } = verification_result else {
        return Err(ErrorResponse::unauthenticated());
    };

    let public_key: PersistedPublicKey = {
        let database = state.pool.get().await.internal_server_error()?;

        let transports: Vec<_> = response
            .method_results
            .transports
            .iter()
            .map(|transport| transport.to_string())
            .collect();

        let signature_counter: i64 = response
            .method_results
            .authenticator_data
            .signature_counter
            .into();

        #[allow(clippy::as_conversions)]
        let algorithm = response.method_results.public_key_algorithm as i32;

        database
            .query_one(
                CreatePublicKey::QUERY,
                CreatePublicKey::params(
                    &credential.raw_id,
                    &identity_id,
                    &display_name,
                    &response.method_results.public_key,
                    &algorithm,
                    &transports,
                    &signature_counter,
                )
                .as_array()
                .as_slice(),
            )
            .await
            .fk_violation(ErrorResponse::unauthenticated)?
            .internal_server_error()?
            .parse()
            .unwrap()
    };

    let mut header_map = HeaderMap::new();
    if token.claims.typ.eq(&TokenType::Provisioning) {
        let token = state
            .signing_jwk
            .issue(token.claims.sub, TokenType::Common)
            .internal_server_error()?;

        let value = HeaderValue::from_str(&format!("bearer {}", token.serialize()))
            .internal_server_error()?;

        header_map.insert(AUTHORIZATION, value);
    }

    Ok((StatusCode::CREATED, header_map, Json(public_key)))
}
