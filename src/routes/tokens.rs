use core::marker::PhantomData;

use axum::extract::State;
use http::{
    StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKey, DecodeBase64, EncodeBase64, ErrorResponse, InternalServerError, Json,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::public_key_credential::{PublicKeyCredential, Response},
};
use ts_sql_helper_lib::SqlTimestamp;

use crate::{ApiState, sql};

pub async fn delete_current_token(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let exp = SqlTimestamp(token.claims.exp);

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;
    connection
        .execute(
            sql::revocation::revoke()[0],
            sql::revocation::RevokeParams {
                p1: &token.claims.tid,
                p2: &exp,
                phantom_data: PhantomData,
            }
            .params()
            .as_slice(),
        )
        .await
        .internal_server_error("execute token revoke")?;

    Ok(StatusCode::NO_CONTENT)
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

pub async fn post_tokens(
    _: ApiKey,
    token: Option<Token>,
    State(state): State<ApiState>,
    Json(body): Json<PostTokensBody>,
) -> Result<(StatusCode, HeaderMap, Json<TokenDetails>), ErrorResponse> {
    let PostTokensBody { credential, typ } = body;

    let response = match credential.response {
        Response::AssertionResponse(ref response) => response,
        _ => return Err(ErrorResponse::bad_request(vec![])),
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

    let is_valid = credential
        .verify(&state, identity_id.as_deref())
        .await
        .internal_server_error("verify credential")?;

    if !is_valid {
        // TODO unauthenticated only makes sense if there is a token
        return Err(ErrorResponse::unauthenticated());
    }

    // TODO update signature counter?

    let mut header_map = HeaderMap::new();
    let (token, signature) = state
        .signing_jwk
        .issue(response.user_handle.encode_base64(), typ)
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
