use core::marker::PhantomData;

use axum::extract::State;
use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InternalServerError, Json, Problem,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::{
        persisted_public_key::PersistedPublicKey,
        public_key_credential::{PublicKeyCredential, Response},
    },
};
use ts_sql_helper_lib::{FromRow, SqlError};

use crate::{ApiState, sql};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicKeyBody {
    credential: PublicKeyCredential,
    display_name: String,
}

pub async fn post_public_keys(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
    Json(body): Json<CreatePublicKeyBody>,
) -> Result<(StatusCode, HeaderMap, Json<PersistedPublicKey>), ErrorResponse> {
    let CreatePublicKeyBody {
        credential,
        display_name,
    } = body;

    if display_name.is_empty() {
        return Err(ErrorResponse::bad_request(vec![Problem::new(
            "/displayName",
            "The display name must not be empty.",
        )]));
    }

    let response = match credential.response {
        Response::AttestationResponse(ref response) => response,
        _ => return Err(ErrorResponse::bad_request(vec![])),
    };

    match token.claims.typ {
        TokenType::Consent { ref act } => {
            if act != "POST /public-keys" {
                return Err(ErrorResponse::unauthenticated());
            }
        }
        TokenType::Provisioning => {}
        _ => return Err(ErrorResponse::unauthenticated()),
    }

    let identity_id = token
        .claims
        .sub
        .decode_base64()
        .internal_server_error("decode token subject")?;

    let is_valid = credential
        .verify(&state, Some(&identity_id))
        .await
        .internal_server_error("verify credential")?;

    if !is_valid {
        return Err(ErrorResponse::unauthenticated());
    }

    let public_key = {
        let connection = state
            .pool
            .get()
            .await
            .internal_server_error("get db connection")?;

        let transports: Vec<_> = response
            .method_results
            .transports
            .iter()
            .map(|transport| transport.to_string())
            .collect();

        let signature_counter = response
            .method_results
            .authenticator_data
            .signature_counter
            .into();

        #[allow(clippy::as_conversions)]
        let algorithm = response.method_results.public_key_algorithm as i32;

        let row = connection
            .query_one(
                sql::public_key::create()[0],
                sql::public_key::CreateParams {
                    p1: &credential.raw_id,
                    p2: &identity_id,
                    p3: &display_name,
                    p4: &response.method_results.public_key,
                    p5: &algorithm,
                    p6: &signature_counter,
                    p7: &transports,
                    phantom_data: PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .fk_violation(ErrorResponse::unauthenticated)?
            .internal_server_error("execute public key create")?;

        PersistedPublicKey::from_row(&row)
            .internal_server_error("convert row to persisted public key")?
    };

    let mut header_map = HeaderMap::new();

    if token.claims.typ.eq(&TokenType::Provisioning) {
        let (token, signature) = state
            .signing_jwk
            .issue(token.claims.sub, TokenType::Common)
            .internal_server_error("issue token")?;

        let header = token
            .header
            .encode()
            .internal_server_error("encode header")?;
        let claims = token
            .claims
            .encode()
            .internal_server_error("encode claims")?;

        let value = HeaderValue::from_str(&format!("{header}.{claims}.{signature}"))
            .internal_server_error("convert token to header value")?;

        header_map.insert(AUTHORIZATION, value);
    }

    Ok((StatusCode::CREATED, header_map, Json(public_key)))
}
