use axum::extract::{Path, Query, State};
use base64ct::{Base64UrlUnpadded, Encoding};
use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InternalServerError, Json, Problem,
    token::{extractor::Token, json_web_token::TokenType},
    webauthn::{
        persisted_public_key::PersistedPublicKey,
        public_key_credential::{PublicKeyCredential, Response, Transports, Type},
        public_key_credential_request_options::AllowCredentials,
        verification::VerificationResult,
    },
};
use ts_sql_helper_lib::{FromRow, SqlError, query};

use crate::{ApiState, routes::revoke_token};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCredentialsResponse {
    pub allow_credentials: Vec<AllowCredentials>,
}

query! {
    name: GetPublicKeyByUsername,
    row: {raw_id: Vec<u8>, transports: Vec<Transports>},
    query: r#"
        SELECT
            raw_id,
            transports
        FROM
            public_keys
        INNER JOIN
            identities
        ON
            identities.id = public_keys.identity_id
        WHERE
            identities.username = $1::VARCHAR;"#
}

pub async fn get_allowed_credentials(
    _: ApiKey,
    Path(username): Path<String>,
    State(state): State<ApiState>,
) -> Result<(StatusCode, Json<AllowCredentialsResponse>), ErrorResponse> {
    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let allow_credentials = connection
        .query(
            GetPublicKeyByUsername::QUERY,
            GetPublicKeyByUsername::params(&username)
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error("get allowed credentials")?
        .into_iter()
        .map(|row| GetPublicKeyByUsernameRow::from_row(&row))
        .collect::<Result<Vec<_>, _>>()
        .internal_server_error("convert row to GetPublicKeyByUsernameRow")?
        .into_iter()
        .map(|credential| AllowCredentials {
            id: credential.raw_id,
            transports: credential.transports,
            r#type: Type::PublicKey,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(AllowCredentialsResponse { allow_credentials }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePublicKeyBody {
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
        TokenType::Provisioning | TokenType::Common => {}
        _ => return Err(ErrorResponse::unauthenticated()),
    }

    let identity_id = token
        .claims
        .sub
        .decode_base64()
        .internal_server_error("decode token subject")?;

    let verification_result = credential
        .verify(&state, Some(&identity_id))
        .await
        .internal_server_error("verify credential")?;

    let VerificationResult::Valid { identity_id } = verification_result else {
        return Err(ErrorResponse::unauthenticated());
    };

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

        let signature_counter: i64 = response
            .method_results
            .authenticator_data
            .signature_counter
            .into();

        #[allow(clippy::as_conversions)]
        let algorithm = response.method_results.public_key_algorithm as i32;

        let row = connection
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

        let value = HeaderValue::from_str(&format!("bearer {header}.{claims}.{signature}"))
            .internal_server_error("convert token to header value")?;

        header_map.insert(AUTHORIZATION, value);
    }

    Ok((StatusCode::CREATED, header_map, Json(public_key)))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeysResponse {
    pub public_keys: Vec<PersistedPublicKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeysQuery {
    pub identity_id: Option<String>,
}

query! {
    name: GetPublicKeys,
    query: r#"
        SELECT
            raw_id,
            identity_id,
            display_name,
            public_key,
            public_key_algorithm,
            transports,
            signature_counter,
            created,
            last_used
        FROM
            public_keys
        WHERE
            identity_id = ANY($1::BYTEA[])
            "#
}

pub async fn get_public_keys(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
    Query(query): Query<PublicKeysQuery>,
) -> Result<(StatusCode, Json<PublicKeysResponse>), ErrorResponse> {
    if token.claims.typ != TokenType::Common {
        return Err(ErrorResponse::unauthenticated());
    }

    let identity_ids = if let Some(query) = query.identity_id {
        let ids = query.split(",");
        ids.filter_map(|id| {
            if id != token.claims.sub {
                return None;
            }

            Some(Base64UrlUnpadded::decode_vec(id))
        })
        .collect::<Result<_, _>>()
        .map_err(|_| ErrorResponse::bad_request(vec![Problem::pointer("/identityId")]))?
    } else {
        vec![
            Base64UrlUnpadded::decode_vec(&token.claims.sub)
                .internal_server_error("decode token sub")?,
        ]
    };

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let public_keys = connection
        .query(
            GetPublicKeys::QUERY,
            GetPublicKeys::params(&identity_ids).as_array().as_slice(),
        )
        .await
        .internal_server_error("get public keys")?
        .into_iter()
        .map(|row| PersistedPublicKey::from_row(&row))
        .collect::<Result<Vec<_>, _>>()
        .internal_server_error("convert public key to persisted public key")?;

    Ok((StatusCode::OK, Json(PublicKeysResponse { public_keys })))
}

query! {
    name: GetPublicKeyCount,
    query: r#"
        SELECT
            COUNT(raw_id) as public_key_count
        FROM
            public_keys
        WHERE
            identity_id = $1::BYTEA"#
}

query! {
    name: DeletePublicKey,
    query: r#"
        DELETE FROM
            public_keys
        WHERE
            raw_id = $1::BYTEA
            AND identity_id = $2::BYTEA"#
}

pub async fn delete_public_key(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
    Path(public_key_id): Path<String>,
) -> Result<StatusCode, ErrorResponse> {
    let expected_consent = TokenType::Consent {
        act: format!("DELETE /public-keys/{public_key_id}"),
    };
    if token.claims.typ != expected_consent {
        return Err(ErrorResponse::unauthenticated());
    }

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get pool connection")?;

    revoke_token(&connection, &token.claims.tid, token.claims.exp).await;

    let identity_id = token
        .claims
        .sub
        .decode_base64()
        .internal_server_error("decode token sub claim")?;

    let public_key_id = public_key_id
        .decode_base64()
        .map_err(|_| ErrorResponse::bad_request(vec![Problem::pointer("/publicKeyId")]))?;

    let row = connection
        .query_one(
            GetPublicKeyCount::QUERY,
            GetPublicKeyCount::params(&identity_id)
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error("query public key count")?;
    let public_key_count: i64 = row
        .try_get("public_key_count")
        .internal_server_error("get public_key_count")?;
    if public_key_count == 0 {
        return Err(ErrorResponse::unauthenticated());
    }
    if public_key_count == 1 {
        return Err(ErrorResponse {
            status: StatusCode::NOT_ACCEPTABLE,
            problems: vec![Problem::detail(
                "an identity must always have at least one credential",
            )],
        });
    }

    connection
        .execute(
            DeletePublicKey::QUERY,
            DeletePublicKey::params(&public_key_id, &identity_id)
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error("delete public key")?;

    Ok(StatusCode::NO_CONTENT)
}
