use core::time::Duration;

use api_helper::{ApiKey, ErrorResponse, InternalServerError, Json, Jwt, Problem};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use jiff::Timestamp;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::{
    ApiState,
    models::{Challenge, PublicKey},
    sql,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialAttestation {
    pub id: String,
    pub raw_id: String,
    pub authenticator_attachment: Option<String>,
    pub r#type: String,
    pub response: AttestationResponse,
    pub public_key: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub attestation_object: Option<String>,
    pub client_data_json: String,  // TODO JSON
    pub transports: Vec<String>,   // TODO schema
    pub public_key_algorithm: i32, // TODO schema
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientData {
    pub r#type: String,
    pub challenge: String,
}

pub async fn post_public_keys(
    State(state): State<ApiState>,
    _: ApiKey,
    Jwt(jwt): Jwt,
    Json(body): Json<PublicKeyCredentialAttestation>,
) -> Result<(StatusCode, HeaderMap, Json<PublicKey>), ErrorResponse> {
    if body.r#type != "public-key" {
        return Err(ErrorResponse::bad_request(vec![Problem::new(
            "$.type",
            "The relying party only accepts public key credentials.",
        )]));
    }

    let client_data: ClientData = {
        let client_data_json_string = BASE64_STANDARD
            .decode(body.response.client_data_json)
            .map_err(|_| ErrorResponse {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                problems: vec![Problem::pointer("$.response.clientDataJSON")],
            })?;

        serde_json::from_slice(&client_data_json_string).map_err(|_| {
            ErrorResponse::bad_request(vec![Problem::new(
                "$.response.clientDataJSON.type",
                "The request contained invalid client data.",
            )])
        })?
    };

    if client_data.r#type != "webauthn.create" {
        return Err(ErrorResponse::bad_request(vec![Problem::new(
            "$.response.clientDataJSON.type",
            "The WebAuthN response type is unsupported for this operation.",
        )]));
    }

    let challenge = {
        let connection = state.pool.get().await.internal_server_error()?;

        let row = connection
            .query_opt(
                sql::challenge::get()[0],
                sql::challenge::GetParams {
                    p1: &client_data.challenge,
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .internal_server_error()?
            .ok_or_else(|| ErrorResponse::not_found(Some("$.response.clientDataJSON.challenge")))?;

        Challenge::from_row(&row).internal_server_error()?
    };

    if challenge.expires.0 < Timestamp::now() - Duration::from_secs(60) {
        return Err(ErrorResponse::not_found(Some(
            "$.response.clientDataJSON.challenge",
        )));
    }

    let identity_id = challenge
        .identity_id
        .ok_or_else(|| ErrorResponse::not_found(Some("$.response.clientDataJSON.challenge")))?;
    if identity_id != jwt.claims.sub {
        return Err(ErrorResponse::not_found(Some(
            "$.response.clientDataJSON.challenge",
        )));
    }

    let public_key = {
        let connection = state.pool.get().await.internal_server_error()?;

        let row = connection
            .query_one(
                sql::public_key::create()[0],
                sql::public_key::CreateParams {
                    p1: &body.raw_id,
                    p2: &identity_id,
                    p3: &body.public_key,
                    p4: &body.response.public_key_algorithm,
                    phantom_data: core::marker::PhantomData, // TODO transport?
                }
                .params()
                .as_slice(),
            )
            .await
            .internal_server_error()?;

        PublicKey::from_row(&row).internal_server_error()?
    };

    let is_first_key = {
        let connection = state.pool.get().await.internal_server_error()?;

        let row = connection
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
            .internal_server_error()?;

        row.len() == 1
    };

    let mut headers = HeaderMap::new();

    if is_first_key {
        // Flag identity as non-expiring
        {
            let connection = state.pool.get().await.internal_server_error()?;

            connection
                .execute(
                    sql::identities::flag_permanant()[0],
                    sql::identities::FlagPermanantParams {
                        p1: &identity_id,
                        phantom_data: core::marker::PhantomData,
                    }
                    .params()
                    .as_slice(),
                )
                .await
                .internal_server_error()?;
        }

        // Create token
        let token = state
            .jwt_encoder
            .encode(jwt.claims.sub.clone(), None)
            .internal_server_error()?;

        headers.append(
            "Authorization",
            HeaderValue::from_str(&format!("bearer {token}")).internal_server_error()?,
        );
    }

    Ok((StatusCode::CREATED, headers, Json(public_key)))
}
