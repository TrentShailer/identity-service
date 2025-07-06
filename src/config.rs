use std::{fs, io, path::PathBuf};

use schemars::{JsonSchema, generate::SchemaSettings};
use serde::{Deserialize, Serialize};
use ts_api_helper::{
    ApiKeyValidationConfig, ConnectionPool, HttpClientConfig, SetupPostgresError,
    setup_connection_pool,
    token::config::{TokenIssuingConfig, TokenValidationConfig},
    webauthn::public_key_credential_creation_options::RelyingParty,
};
use ts_rust_helper::config::ConfigFile;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// The URL to reach the database at.
    /// This should be in the form `postgres://username:password@localhost:5432`
    database_url: String,

    /// The relying party for WebAuthN.
    pub relying_party: RelyingParty,

    /// The token issuing config.
    pub token_issuing_config: TokenIssuingConfig,

    /// The token validating config.
    pub token_validating_config: TokenValidationConfig,

    /// The API key validation config.
    pub api_key_validation_config: ApiKeyValidationConfig,

    /// The HTTP client config.
    pub http_client_config: HttpClientConfig,

    /// The CORS allowed origins.
    pub allowed_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "postgres://username:password@localhost:5432".to_string(),
            token_issuing_config: Default::default(),
            token_validating_config: Default::default(),
            api_key_validation_config: Default::default(),
            http_client_config: Default::default(),
            relying_party: RelyingParty {
                id: "relying.party.id".to_string(),
                name: "Identity Provider Name".to_string(),
            },
            allowed_origins: vec![
                "http://localhost:5500".to_string(),
                "http://127.0.0.1:5500".to_string(),
            ],
        }
    }
}

impl Config {
    pub async fn database_pool(&self) -> Result<ConnectionPool, SetupPostgresError> {
        setup_connection_pool(&self.database_url).await
    }
}

impl ConfigFile for Config {
    fn config_file_path() -> PathBuf {
        PathBuf::from("./config.json")
    }

    fn schema() -> serde_json::Value {
        let settings = SchemaSettings::draft07();
        let generator = settings.into_generator();
        let schema = generator.into_root_schema_for::<Self>();
        serde_json::to_value(schema).unwrap()
    }

    fn delete(&self) -> io::Result<()> {
        fs::remove_file(PathBuf::from("./config.json"))
    }

    fn write(&self) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(PathBuf::from("./config.json"), &json)
    }
}
