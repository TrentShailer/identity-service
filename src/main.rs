//! Personal identity provider and authorisation server.

use core::str::FromStr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};
use http::{HeaderName, Uri};
use reqwest::Client;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use ts_api_helper::{
    ApiKeyValidationConfig, ConnectionPool, HasApiKeyValidationConfig, HasHttpClient, cors_layer,
    token::{
        JsonWebKeySetCache, SigningJsonWebKey,
        extractor::{HasKeySetCache, HasRevocationEndpoint},
        json_web_key::JsonWebKeySet,
    },
    webauthn::{
        self, challenge::Challenge, persisted_public_key::PersistedPublicKey,
        public_key_credential_creation_options::RelyingParty,
    },
};
use ts_rust_helper::{
    command::{Cli, Command},
    config::try_load_config,
    error::{IntoErrorReport, ReportProgramExit},
};
use ts_sql_helper_lib::FromRow;

use crate::config::Config;

mod config;
mod models;
mod routes;
mod sql;

#[derive(Debug, Clone)]
pub struct ApiState {
    pub pool: ConnectionPool,
    pub jwks_file: JsonWebKeySet,
    pub signing_jwk: Arc<SigningJsonWebKey>,
    pub jwks_cache: JsonWebKeySetCache,
    pub api_key_config: ApiKeyValidationConfig,
    pub http_client: Client,
    pub revocation_endpoint: String,
    pub relying_party: RelyingParty,
}

impl HasKeySetCache for ApiState {
    fn jwks_cache(&self) -> &JsonWebKeySetCache {
        &self.jwks_cache
    }
}
impl HasApiKeyValidationConfig for ApiState {
    fn api_key_config(&self) -> &ApiKeyValidationConfig {
        &self.api_key_config
    }
}
impl HasHttpClient for ApiState {
    fn http_client(&self) -> &Client {
        &self.http_client
    }
}
impl HasRevocationEndpoint for ApiState {
    fn revocation_endpoint(&self) -> &str {
        &self.revocation_endpoint
    }
}
impl webauthn::verification::Verifier for ApiState {
    type Error = VerifierError;

    async fn get_challenge(&self, challenge: &[u8]) -> Result<Option<Challenge>, Self::Error> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(VerifierError::pool_connection)?;

        let row = connection
            .query_opt(
                sql::challenge::take()[0],
                sql::challenge::TakeParams {
                    p1: challenge,
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .map_err(VerifierError::query_challenge)?;

        match row {
            Some(row) => Ok(Some(
                Challenge::from_row(&row).map_err(VerifierError::challenge_from_row)?,
            )),
            None => Ok(None),
        }
    }

    async fn get_public_key(
        &self,
        raw_id: &[u8],
    ) -> Result<Option<PersistedPublicKey>, Self::Error> {
        let connection = self
            .pool
            .get()
            .await
            .map_err(VerifierError::pool_connection)?;

        let row = connection
            .query_opt(
                sql::public_key::get_by_id()[0],
                sql::public_key::GetByIdentityParams {
                    p1: raw_id,
                    phantom_data: core::marker::PhantomData,
                }
                .params()
                .as_slice(),
            )
            .await
            .map_err(VerifierError::query_public_key)?;

        match row {
            Some(row) => Ok(Some(
                PersistedPublicKey::from_row(&row).map_err(VerifierError::public_key_from_row)?,
            )),
            None => Ok(None),
        }
    }

    fn relying_party_id(&self) -> &str {
        &self.relying_party.id
    }
}
/// Error variants for WebAuthN response verification.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum VerifierError {
    #[non_exhaustive]
    PoolConnection {
        source: bb8::RunError<tokio_postgres::Error>,
    },

    #[non_exhaustive]
    QueryChallenge { source: tokio_postgres::Error },

    #[non_exhaustive]
    QueryPublicKey { source: tokio_postgres::Error },

    #[non_exhaustive]
    ChallengeFromRow { source: tokio_postgres::Error },

    #[non_exhaustive]
    PublicKeyFromRow { source: tokio_postgres::Error },
}
impl core::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            Self::PoolConnection { .. } => write!(f, "could not get a connection from the pool"),
            Self::QueryChallenge { .. } => write!(f, "could not query the challenge"),
            Self::QueryPublicKey { .. } => write!(f, "could not query the public key"),
            Self::ChallengeFromRow { .. } => {
                write!(f, "could not convert the row into a challenge")
            }
            Self::PublicKeyFromRow { .. } => {
                write!(f, "could not convert the row into a public key")
            }
        }
    }
}
impl core::error::Error for VerifierError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self {
            Self::PoolConnection { source, .. } => Some(source),
            Self::QueryChallenge { source, .. } => Some(source),
            Self::QueryPublicKey { source, .. } => Some(source),
            Self::ChallengeFromRow { source, .. } => Some(source),
            Self::PublicKeyFromRow { source, .. } => Some(source),
        }
    }
}
impl VerifierError {
    #[allow(missing_docs)]
    pub fn pool_connection(source: bb8::RunError<tokio_postgres::Error>) -> Self {
        Self::PoolConnection { source }
    }

    #[allow(missing_docs)]
    pub fn query_challenge(source: tokio_postgres::Error) -> Self {
        Self::QueryChallenge { source }
    }

    #[allow(missing_docs)]
    pub fn query_public_key(source: tokio_postgres::Error) -> Self {
        Self::QueryPublicKey { source }
    }

    #[allow(missing_docs)]
    pub fn public_key_from_row(source: tokio_postgres::Error) -> Self {
        Self::PublicKeyFromRow { source }
    }

    #[allow(missing_docs)]
    pub fn challenge_from_row(source: tokio_postgres::Error) -> Self {
        Self::ChallengeFromRow { source }
    }
}

#[tokio::main]
async fn main() -> ReportProgramExit {
    let cli = Cli::parse();

    let filter = tracing_subscriber::filter::LevelFilter::from_level(Level::INFO);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer()) // TODO verbose
        .with(filter)
        .init();

    if let Some(subcommand) = cli.subcommand {
        match subcommand {
            Command::Config(config_subcommand) => {
                config_subcommand
                    .execute::<Config>()
                    .into_report("execute config command")?;

                eprintln!(
                    "Performed `config {}`",
                    format!("{config_subcommand:?}").to_lowercase()
                );

                return Ok(());
            }
        }
    }

    let config: Config = try_load_config().into_report("load config")?;

    // Setup database pool
    let pool = config
        .database_pool()
        .await
        .into_report("setup database connection pool")?;

    // Migrate database
    {
        let connection = pool
            .get()
            .await
            .into_report("get database pool connection")?;

        for migration in sql::migrations::migrate() {
            connection
                .execute(migration, &[])
                .await
                .into_report("execute migration")?;
        }
    }

    let state = {
        let jwks_file = config
            .token_issuing_config
            .jwks()
            .into_report("load JWKS")?;

        let signing_jwk = Arc::new(
            config
                .token_issuing_config
                .signing_jwk()
                .into_report("load signing key")?,
        );

        let jwks_cache = config.token_validating_config.jwks_cache();

        let api_key_config = config.api_key_validation_config.clone();

        let http_client = config
            .http_client_config
            .http_client()
            .into_report("create HTTP client")?;

        let revocation_endpoint = config.token_validating_config.revocation_endpoint;

        let relying_party = config.relying_party;

        ApiState {
            pool,
            jwks_file,
            signing_jwk,
            jwks_cache,
            api_key_config,
            http_client,
            revocation_endpoint,
            relying_party,
        }
    };

    // TODO repeating task to remove expired identities
    // TODO how are other services going to know when an identity has been deleted?
    // TODO ^ shared database? Event stream?

    let origins: Vec<_> = config
        .allowed_origins
        .iter()
        .map(Uri::try_from)
        .collect::<Result<_, _>>()
        .into_report("convert allowed origin to URI")?;

    let cors = cors_layer(
        origins,
        &[
            HeaderName::from_str(&config.api_key_validation_config.header)
                .into_report("convert API Key header into a HeaderName")?,
        ],
        &[],
    );

    let app = Router::new()
        .route("/.well-known/jwks.json", get(routes::get_well_known_jwks))
        .route("/revoked-tokens/{tokenId}", get(routes::get_revoked_token))
        .route(
            "/tokens/current",
            delete(routes::delete_current_token).get(routes::get_current_token),
        )
        .route("/tokens", post(routes::post_tokens))
        .route("/identities", post(routes::post_identities))
        .route("/challenges", post(routes::post_challenges))
        .route(
            "/credential-creation-options",
            get(routes::get_credential_creation_options),
        )
        .route(
            "/credential-request-options",
            get(routes::get_credential_request_options),
        )
        .route("/public-keys", post(routes::post_public_keys))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.into_report("axum serve")?;

    Ok(())
}
