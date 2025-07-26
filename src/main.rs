//! Personal identity provider and authorisation server.

use core::str::FromStr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};
use http::{HeaderName, Uri};
use tokio_postgres::GenericClient;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use ts_api_helper::cors_layer;
use ts_rust_helper::{
    command::{Cli, Command},
    config::try_load_config,
    error::{IntoErrorReport, ReportProgramExit},
};
use ts_sql_helper_lib::perform_migrations_async;

use crate::config::Config;

pub use crate::state::ApiState;

mod config;
mod models;
mod routes;
mod state;

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

        perform_migrations_async(connection.client(), None)
            .await
            .into_report("execute migrations")?;
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
    /*
    DELETE FROM
      identities
    WHERE
      expires > timezone('utc', NOW())
    RETURNING
      id;

    DELETE FROM
      challenges
    WHERE
      expires > timezone('utc', NOW());

    DELETE FROM
      revocations
    WHERE
      expires > timezone('utc', NOW());

         */

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

    #[rustfmt::skip]
    let app = Router::new()
        .route("/.well-known/jwks.json", get(routes::get_well_known_jwks))
        .route("/revoked-tokens/{tokenId}", get(routes::get_revoked_token))
        .route("/tokens/current", delete(routes::delete_current_token).get(routes::get_current_token))
        .route("/tokens", post(routes::post_tokens))
        .route("/identities", post(routes::post_identities))
        .route("/identities/{identityId}", get(routes::get_identity))
        .route("/challenges", post(routes::post_challenges))
        .route("/credential-creation-options", get(routes::get_credential_creation_options))
        .route("/credential-request-options", get(routes::get_credential_request_options))
        .route("/allowed-credentials/{username}", get(routes::get_allowed_credentials))
        .route("/public-keys", post(routes::post_public_keys).get(routes::get_public_keys))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.into_report("axum serve")?;

    Ok(())
}
