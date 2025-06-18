use std::{
    env, fs,
    sync::{Arc, LazyLock},
};

use api_helper::{ApiKeyConfig, ApiKeyState, Jwks, JwksState, JwtEncoder, setup_connection_pool};
use axum::{
    Router,
    http::{HeaderMap, HeaderValue},
    routing::post,
};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use jsonwebtoken::{Algorithm, EncodingKey};
use reqwest::Client;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

mod config;
mod identity;
mod routes;
mod sql;

#[derive(Clone)]
pub struct ApiState {
    pub jwks: Arc<Mutex<Jwks>>,
    pub jwt_encoder: JwtEncoder,
    pub pool: Pool<PostgresConnectionManager<NoTls>>,
    pub api_key_config: ApiKeyConfig,
}

impl JwksState for ApiState {
    fn jwks(&self) -> Arc<Mutex<Jwks>> {
        self.jwks.clone()
    }
}
impl ApiKeyState for ApiState {
    fn api_key_config(&self) -> &ApiKeyConfig {
        &self.api_key_config
    }
}

#[tokio::main]
async fn main() {
    if env::args().any(|arg| arg == "--init") {
        Config::write_default().unwrap();
        return;
    }

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    static CONFIG: LazyLock<Config> = std::sync::LazyLock::new(|| Config::read().unwrap());

    // Setup database
    let pool = {
        let pool = setup_connection_pool(&CONFIG.database_url).await.unwrap();

        // Migrate database
        let connection = pool.get().await.unwrap();
        for migration in sql::migrations::migrate() {
            connection.execute(migration, &[]).await.unwrap();
        }
        drop(connection);

        pool
    };

    // Setup JWKS
    let jwks = {
        let mut headers = HeaderMap::new();
        headers.append(
            CONFIG.api_key_header.as_str(),
            HeaderValue::from_str(&CONFIG.api_key).unwrap(),
        );
        let client = Client::builder().default_headers(headers).build().unwrap();

        Arc::new(Mutex::new(Jwks::new(
            "localhost:8081/.well-known/jwks.json".to_string(),
            client,
        )))
    };

    // Setup JWT encoder
    let jwt_encoder = {
        let kid = CONFIG.jwk_kid.clone();
        let algorithm = CONFIG.jwk_algorithm;

        let key_file = fs::read(&CONFIG.jwk_path).unwrap();
        let encoding_key = match algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                EncodingKey::from_secret(&key_file)
            }

            Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(&key_file).unwrap(),

            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => EncodingKey::from_rsa_pem(&key_file).unwrap(),

            Algorithm::EdDSA => EncodingKey::from_ed_pem(&key_file).unwrap(),
        };

        JwtEncoder {
            algorithm,
            kid,
            encoding_key,
            expires_in_seconds: 60 * 24 * 30,
            issuer: "identity-service".to_string(),
        }
    };

    // Setup API key config
    let api_key_config = ApiKeyConfig {
        allowed_api_keys: CONFIG.allowed_api_keys.clone(),
        header: CONFIG.api_key_header.clone(),
    };

    let state = ApiState {
        jwks,
        pool,
        jwt_encoder,
        api_key_config,
    };

    let app = Router::new()
        .route("/", post(routes::post_identity))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
