use api_helper::Json;
use axum::extract::State;
use reqwest::StatusCode;
use serde::Serialize;

use crate::ApiState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialCreationOptions {
    pub attestation: Option<&'static str>,
    pub attestation_formats: Option<Vec<&'static str>>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub exclude_credentials: Option<Vec<ExcludeCredential>>,
    pub extensions: Option<()>,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub rp: RelyingParty,
    pub timeout: Option<i32>,
    pub hints: Option<Vec<&'static str>>,
}
#[derive(Debug, Serialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<&'static str>,
    pub require_resident_key: Option<bool>,
    pub resident_key: Option<&'static str>,
    pub user_verification: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct ExcludeCredential {
    pub id: String,
    pub transports: Option<Vec<String>>,
    pub r#type: String,
}
#[derive(Debug, Serialize)]
pub struct PubKeyCredParams {
    pub alg: i32,
    pub r#type: &'static str,
}
#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub id: Option<String>,
    pub name: &'static str,
}

pub async fn get_credential_creation_options(
    State(state): State<ApiState>,
) -> (StatusCode, Json<CredentialCreationOptions>) {
    let options = CredentialCreationOptions {
        attestation: Some("none"), // TODO update schema?
        attestation_formats: None,
        authenticator_selection: Some(AuthenticatorSelection {
            authenticator_attachment: None,
            require_resident_key: Some(true),
            resident_key: Some("required"),
            user_verification: Some("preferred"),
        }),
        exclude_credentials: None,
        extensions: None,
        pub_key_cred_params: vec![
            PubKeyCredParams {
                alg: -7, // `ES256`
                r#type: "public-key",
            },
            PubKeyCredParams {
                alg: -8, // `EdDSA`
                r#type: "public-key",
            },
            PubKeyCredParams {
                alg: -19, // `Ed25519`
                r#type: "public-key",
            },
            PubKeyCredParams {
                alg: -35, // TODO `ES384`?
                r#type: "public-key",
            },
            PubKeyCredParams {
                alg: -36, // TODO `ES512`?
                r#type: "public-key",
            },
            PubKeyCredParams {
                alg: -257, // `RS256`
                r#type: "public-key",
            },
        ],
        rp: RelyingParty {
            id: Some(state.rp_id),
            name: "TS Auth",
        },
        timeout: Some(1000 * 60 * 15),
        hints: Some(vec!["security-key", "hybrid", "client-device"]),
    };

    (StatusCode::OK, Json(options))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequestOptions {
    pub allow_credentials: Option<Vec<AllowCredential>>,
    pub extensions: Option<()>,
    pub hints: Option<Vec<&'static str>>,
    pub rp_id: Option<String>,
    pub timeout: Option<i32>,
    pub user_verification: Option<&'static str>,
}
#[derive(Debug, Serialize)]
pub struct AllowCredential {
    pub id: String,
    pub transports: Vec<String>,
    pub r#type: String,
}

pub async fn get_credential_request_options(
    State(state): State<ApiState>,
) -> (StatusCode, Json<CredentialRequestOptions>) {
    let options = CredentialRequestOptions {
        allow_credentials: None,
        extensions: None,
        hints: Some(vec!["security-key", "hybrid", "client-device"]),
        rp_id: Some(state.rp_id),
        timeout: Some(1000 * 60 * 15),
        user_verification: Some("preferred"),
    };
    (StatusCode::OK, Json(options))
}
