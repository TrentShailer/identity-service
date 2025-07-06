use axum::extract::{Query, State};
use http::StatusCode;
use serde::Deserialize;
use ts_api_helper::{
    ApiKey, DecodeBase64, ErrorResponse, InternalServerError, Json,
    token::extractor::Token,
    webauthn::{
        persisted_public_key::PersistedPublicKey,
        public_key_credential::{Hint, Type, UserVerification},
        public_key_credential_creation_options::{
            Attestation, AuthenticatorSelection, ExcludeCredentials, Extensions,
            PublicKeyCredentialCreationOptions, PublicKeyParameters, ResidentKey, User,
        },
        public_key_credential_request_options::{
            AllowCredentials, PublicKeyCredentialRequestOptions,
        },
    },
};
use ts_rust_helper::error::{ErrorLogger, IntoErrorReport};
use ts_sql_helper_lib::FromRow;

use crate::{ApiState, models::Identity, sql};

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

    let identity = {
        let connection = state
            .pool
            .get()
            .await
            .internal_server_error("get db connection")?;
        let row = connection
            .query_opt(
                sql::identities::get_by_id()[0],
                sql::identities::GetByIdParams {
                    p1: &identity_id,
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .internal_server_error("query identity by id")?;

        match row {
            Some(row) => {
                Identity::from_row(&row).internal_server_error("convert row to identity")?
            }
            None => return Err(ErrorResponse::unauthenticated()),
        }
    };

    let exclude_credentials = {
        let connection = state
            .pool
            .get()
            .await
            .internal_server_error("get db connection")?;
        let rows = connection
            .query(
                sql::public_key::get_by_identity()[0],
                sql::public_key::GetByIdentityParams {
                    p1: &identity_id,
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .internal_server_error("get public key by identity")?;

        rows.into_iter()
            .filter_map(|row| {
                PersistedPublicKey::from_row(&row)
                    .into_report("convert row to public key")
                    .log_error()
                    .ok()
            })
            .map(|key| ExcludeCredentials {
                id: key.raw_id,
                transports: Some(key.transports),
                r#type: Type::PublicKey,
            })
            .collect::<Vec<_>>()
    };

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

            let identity_row = connection
                .query_opt(
                    sql::identities::get_by_username()[0],
                    sql::identities::GetByUsernameParams {
                        p1: username,
                        phantom_data: core::marker::PhantomData,
                    }
                    .params()
                    .as_slice(),
                )
                .await
                .internal_server_error("query identity by username")?
                .ok_or_else(|| ErrorResponse::not_found(Some("/username")))?;

            let identity = Identity::from_row(&identity_row)
                .internal_server_error("convert row to identity")?;

            let allow_credentials = connection
                .query(
                    sql::public_key::get_by_identity()[0],
                    sql::public_key::GetByIdentityParams {
                        p1: &identity.id,
                        phantom_data: core::marker::PhantomData,
                    }
                    .params()
                    .as_slice(),
                )
                .await
                .internal_server_error("query public key by identity")?
                .into_iter()
                .filter_map(|row| {
                    PersistedPublicKey::from_row(&row)
                        .into_report("convert row to public key")
                        .log_error()
                        .ok()
                })
                .map(|key| AllowCredentials {
                    id: key.raw_id,
                    transports: key.transports,
                    r#type: Type::PublicKey,
                })
                .collect::<Vec<_>>();

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
