use std::sync::Arc;

use reqwest::Client;
use ts_api_helper::{
    ApiKeyValidationConfig, ConnectionPool, HasApiKeyValidationConfig, HasHttpClient,
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
use ts_sql_helper_lib::{FromRow, query};

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

query! {
    name: TakeChallenge,
    query: r#"
        DELETE FROM
            challenges
        WHERE
            challenge = $1::BYTEA
        RETURNING
            challenge,
            identity_id,
            origin,
            issued,
            expires;"#
}

query! {
    name: GetPublicKey,
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
            raw_id = $1::BYTEA;"#
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
                TakeChallenge::QUERY,
                TakeChallenge::params(challenge).as_array().as_slice(),
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
                GetPublicKey::QUERY,
                GetPublicKey::params(raw_id).as_array().as_slice(),
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
