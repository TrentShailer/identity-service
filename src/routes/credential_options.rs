use axum::extract::{Query, State};
use http::StatusCode;
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InternalServerError, Json,
    token::extractor::Token,
    webauthn::{
        public_key_credential::{Hint, Transports, Type, UserVerification},
        public_key_credential_creation_options::{
            Attestation, AuthenticatorSelection, ExcludeCredentials, Extensions,
            PublicKeyCredentialCreationOptions, PublicKeyParameters, ResidentKey, User,
        },
        public_key_credential_request_options::{
            AllowCredentials, PublicKeyCredentialRequestOptions,
        },
    },
};
use ts_sql_helper_lib::{FromRow, ParseFromRow, query};

use crate::ApiState;

query! {
    name: GetIdentity,
    row: {id: Vec<u8>, username: String, display_name: String},
    query: r#"
        SELECT
            id,
            username,
            display_name
        FROM
            identities
        WHERE
            id = $1::BYTEA;"#
}

query! {
    name: GetExcludedCredentials,
    row: {raw_id: Vec<u8>, transports: Vec<Transports>},
    query: r#"
        SELECT
            raw_id,
            transports
        FROM
            public_keys
        WHERE
            identity_id = $1::BYTEA"#
}

pub async fn get_credential_creation_options(
    _: ApiKey,
    Token(token): Token,
    State(state): State<ApiState>,
) -> Result<(StatusCode, Json<PublicKeyCredentialCreationOptions>), ErrorResponse> {
    let identity_id = token
        .claims
        .sub
        .decode_base64()
        .internal_server_error("decode token subject")?;

    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let identity = connection
        .query_opt(
            GetIdentity::QUERY,
            GetIdentity::params(&identity_id).as_array().as_slice(),
        )
        .await
        .internal_server_error("query identity by id")?
        .ok_or_else(ErrorResponse::unauthenticated)?
        .parse::<GetIdentityRow>()
        .internal_server_error("convert row to identity row")?;

    let exclude_credentials = connection
        .query(
            GetExcludedCredentials::QUERY,
            GetExcludedCredentials::params(&identity_id)
                .as_array()
                .as_slice(),
        )
        .await
        .internal_server_error("get excluded credentials")?
        .into_iter()
        .map(|row| GetExcludedCredentialsRow::from_row(&row))
        .collect::<Result<Vec<_>, _>>()
        .internal_server_error("convert row to excluded credentials")?
        .into_iter()
        .map(|credential| ExcludeCredentials {
            id: credential.raw_id,
            transports: Some(credential.transports),
            r#type: Type::PublicKey,
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(PublicKeyCredentialCreationOptions {
            attestation: Some(Attestation::None),
            attestation_formats: None,
            authenticator_selection: Some(AuthenticatorSelection {
                authenticator_attachment: None,
                #[allow(deprecated)]
                require_resident_key: Some(false),
                resident_key: Some(ResidentKey::Preferred),
                user_verification: Some(UserVerification::Required),
            }),
            challenge: None,
            exclude_credentials: Some(exclude_credentials),
            extensions: Some(Extensions {
                return_credential_properties: Some(true),
            }),
            public_key_parameters: PublicKeyParameters::ALL.to_vec(),
            relying_party: state.relying_party,
            timeout: 1000 * 60 * 15,
            user: User {
                display_name: identity.display_name,
                id: identity.id,
                name: identity.username,
            },
            hints: Some(vec![Hint::SecurityKey, Hint::ClientDevice, Hint::Hybrid]),
        }),
    ))
}

#[derive(Deserialize)]
pub struct RequestQuery {
    pub username: Option<String>,
}

query! {
    name: GetPublicKeyByUsername,
    row: {raw_id: Vec<u8>, transports: Vec<Transports>},
    query: r#"
        SELECT
            id,
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

pub async fn get_credential_request_options(
    _: ApiKey,
    State(state): State<ApiState>,
    query: Query<RequestQuery>,
) -> Result<(StatusCode, Json<PublicKeyCredentialRequestOptions>), ErrorResponse> {
    let allow_credentials = match &query.username {
        Some(username) => {
            let connection = state
                .pool
                .get()
                .await
                .internal_server_error("get db connection")?;

            let allow_credentials = connection
                .query(
                    GetPublicKeyByUsername::QUERY,
                    GetPublicKeyByUsername::params(username)
                        .as_array()
                        .as_slice(),
                )
                .await
                .internal_server_error("get allow credentials")?
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

            Some(allow_credentials)
        }
        None => None,
    };

    Ok((
        StatusCode::OK,
        Json(PublicKeyCredentialRequestOptions {
            allow_credentials,
            challenge: None,
            extensions: None,
            hints: Some(vec![Hint::SecurityKey, Hint::ClientDevice, Hint::Hybrid]),
            relying_party_id: Some(state.relying_party.id),
            timeout: 1000 * 60 * 15,
            user_verification: Some(UserVerification::Required),
        }),
    ))
}
