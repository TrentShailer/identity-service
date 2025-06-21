use core::marker::PhantomData;

use api_helper::{ApiKey, ErrorResponse, Json, Jwt, ReportUnexpected};
use axum::extract::{Path, State};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiState,
    models::{Identity, PublicKey},
    sql,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialCreationOptions {
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelection,
    pub challenge: Vec<u8>,
    pub exclude_credentials: Vec<ExcludeCredentials>,
    pub public_key_cred_params: PublicKeyCredParams,
    pub rp: RelyingParty,
    pub timeout: u64,
    pub user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub resident_key: String,
    pub user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludeCredentials {
    pub id: Vec<u8>,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredParams {
    pub alg: i32,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub display_name: String,
    pub name: String,
}

pub async fn credential_creation_options(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ApiKey(_): ApiKey,
    Jwt(jwt): Jwt,
) -> Result<(StatusCode, Json<CredentialCreationOptions>), ErrorResponse> {
    if id != jwt.claims.sub {
        return Err(ErrorResponse::not_found());
    }

    let connection = state
        .pool
        .get()
        .await
        .report_error("get database connection")
        .map_err(|_| ErrorResponse::server_error())?;

    let row = connection
        .query_opt(
            sql::identities::get_by_id()[0],
            sql::identities::GetByUsernameParams {
                param_0: id.as_str(),
                phantom_data: PhantomData,
            }
            .params()
            .as_slice(),
        )
        .await
        .map_err(|_| ErrorResponse::server_error())?
        .ok_or_else(ErrorResponse::not_found)?;

    let identity = Identity::from_row(&row).ok_or_else(ErrorResponse::server_error)?;

    // Create challenge
    let mut challenge = vec![0u8; 32];
    let mut rand = StdRng::from_rng(&mut rand::rng());
    rand.fill_bytes(&mut challenge);

    // Insert challenge
    let challenge_id = format!("ts-challenge-{}", Uuid::new_v4());
    connection
        .execute(
            sql::challenge::create()[0],
            sql::challenge::CreateParams {
                param_0: challenge_id.as_str(),
                param_1: id.as_str(),
                param_2: challenge.as_slice(),
                phantom_data: PhantomData,
            }
            .params()
            .as_slice(),
        )
        .await
        .report_error("insert challenge")
        .map_err(|_| ErrorResponse::server_error())?;

    // Get already associated credentials
    let exclude_credentials: Vec<_> = connection
        .query(
            sql::public_key::get_by_identity()[0],
            sql::public_key::GetByIdentityParams {
                param_0: id.as_str(),
                phantom_data: PhantomData,
            }
            .params()
            .as_slice(),
        )
        .await
        .report_error("get public keys")
        .map_err(|_| ErrorResponse::server_error())?
        .iter()
        .filter_map(|row| {
            PublicKey::from_row(row).map(|public_key| ExcludeCredentials {
                id: public_key.raw_id,
                r#type: "public-key".to_string(),
            })
        })
        .collect();

    let credential_creation_options = CredentialCreationOptions {
        attestation: "direct".to_string(),
        authenticator_selection: AuthenticatorSelection {
            resident_key: "required".to_string(),
            user_verification: "preferred".to_string(),
        },
        challenge,
        exclude_credentials,
        public_key_cred_params: PublicKeyCredParams {
            alg: -7,
            r#type: "public-key".to_string(),
        },
        rp: RelyingParty {
            id: "trentshailer.com".to_string(),
            name: "TS web apps".to_string(),
        },
        timeout: 1000 * 60 * 15,
        user: User {
            id: identity.id,
            display_name: identity.display_name,
            name: identity.username,
        },
    };

    Ok((StatusCode::OK, Json(credential_creation_options)))
}
