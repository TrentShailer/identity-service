use axum::extract::State;
use http::{
    StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio_postgres::Client;
use ts_api_helper::{
    ApiKey, DecodeBase64, EncodeBase64, ErrorResponse, InternalServerError, Json,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::{
        public_key_credential::{PublicKeyCredential, Response},
        verification::VerificationResult,
    },
};
use ts_rust_helper::error::ErrorLogger;
use ts_sql_helper_lib::{SqlTimestamp, query};

use crate::ApiState;

query! {
    name: RevokeToken,
    query: r#"
        INSERT INTO
            revocations (token, expires)
        VALUES
            ($1::VARCHAR, $2::TIMESTAMPTZ);"#
}

pub async fn delete_current_token(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;
    if !revoke_token(&connection, &token.claims.tid, token.claims.exp).await {
        return Err(ErrorResponse::internal_server_error());
    };

    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_token(client: &Client, token_id: &str, expiry: Timestamp) -> bool {
    client
        .execute(
            RevokeToken::QUERY,
            RevokeToken::params(token_id, &SqlTimestamp(expiry))
                .as_array()
                .as_slice(),
        )
        .await
        .log_error()
        .is_ok()
}

#[derive(Serialize)]
pub struct TokenDetails {
    pub sub: String,
    #[serde(flatten)]
    pub typ: TokenType,
    pub exp: Timestamp,
}

pub async fn get_current_token(
    _: ApiKey,
    token: Option<Token>,
) -> Result<(StatusCode, Json<TokenDetails>), ErrorResponse> {
    let Some(Token(token)) = token else {
        return Err(ErrorResponse::unauthenticated());
    };
    let details = TokenDetails {
        sub: token.claims.sub,
        typ: token.claims.typ,
        exp: token.claims.exp,
    };

    Ok((StatusCode::OK, Json(details)))
}

#[derive(Deserialize)]
pub struct PostTokensBody {
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

pub async fn post_tokens(
    _: ApiKey,
    token: Option<Token>,
    State(state): State<ApiState>,
    Json(body): Json<PostTokensBody>,
) -> Result<(StatusCode, HeaderMap, Json<TokenDetails>), ErrorResponse> {
    let PostTokensBody { credential, typ } = body;

    let Response::AssertionResponse(assertion_response) = &credential.response else {
        return Err(ErrorResponse::bad_request(vec![]));
    };

    match typ {
        TokenType::Common | TokenType::Consent { .. } => {}
        _ => return Err(ErrorResponse::bad_request(vec![])),
    }

    let identity_id = match token.as_ref() {
        Some(token) => Some(
            token
                .0
                .claims
                .sub
                .decode_base64()
                .internal_server_error("decode token subject")?,
        ),
        None => None,
    };

    let verification_result = credential
        .verify(&state, identity_id.as_deref())
        .await
        .internal_server_error("verify credential")?;

    let VerificationResult::Valid { identity_id } = verification_result else {
        return Err(ErrorResponse::unauthenticated());
    };

    {
        let connection = state
            .pool
            .get()
            .await
            .internal_server_error("get database connection")?;
        connection
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
            .internal_server_error("update public key")?;
    }

    let mut header_map = HeaderMap::new();
    let (token, signature) = state
        .signing_jwk
        .issue(identity_id.encode_base64(), typ)
        .internal_server_error("issue token")?;

    let header = token
        .header
        .encode()
        .internal_server_error("encode header")?;
    let claims = token
        .claims
        .encode()
        .internal_server_error("encode claims")?;

    let value = HeaderValue::from_str(&format!("bearer {header}.{claims}.{signature}"))
        .internal_server_error("convert token to header value")?;

    header_map.insert(AUTHORIZATION, value);

    Ok((
        StatusCode::CREATED,
        header_map,
        Json(TokenDetails {
            sub: token.claims.sub,
            typ: token.claims.typ,
            exp: token.claims.exp,
        }),
    ))
}
