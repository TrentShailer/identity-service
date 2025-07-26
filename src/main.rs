//! Personal identity provider and authorisation server.

use core::{str::FromStr, time::Duration};
use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};
use http::{HeaderName, Uri};
use tokio::task;
use tokio_postgres::{Client, GenericClient};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use ts_api_helper::cors_layer;
use ts_rust_helper::{
    command::{Cli, Command},
    config::try_load_config,
    error::{ErrorLogger, IntoErrorReport, ReportProgramExit},
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

    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let filter = tracing_subscriber::filter::LevelFilter::from_level(level);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true),
        )
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
            pool: pool.clone(),
            jwks_file,
            signing_jwk,
            jwks_cache,
            api_key_config,
            http_client,
            revocation_endpoint,
            relying_party,
        }
    };

    // Repeating task to remove expired items
    let _cleanup_task = {
        let pool = pool.clone();
        task::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));

            loop {
                {
                    let Ok(connection) = pool.get().await.log_error() else {
                        interval.tick().await;
                        continue;
                    };
                    cleanup(&connection).await;
                }
                interval.tick().await;
            }
        })
    };

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
        .route("/identities/{identityId}", get(routes::get_identity).delete(routes::delete_identity))
        .route("/challenges", post(routes::post_challenges))
        .route("/credential-creation-options", get(routes::get_credential_creation_options))
        .route("/credential-request-options", get(routes::get_credential_request_options))
        .route("/allowed-credentials/{username}", get(routes::get_allowed_credentials))
        .route("/public-keys", post(routes::post_public_keys).get(routes::get_public_keys))
        .route("/public-keys/{publicKeyId}", delete(routes::delete_public_key))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.into_report("axum serve")?;

    Ok(())
}

async fn cleanup(client: &Client) {
    let Ok(count) = client
        .execute(
            "DELETE FROM identities WHERE expires > timezone('utc', NOW());",
            &[],
        )
        .await
        .log_error()
    else {
        return;
    };
    if count > 0 {
        tracing::info!("cleaned up {count} identities");
    }

    let Ok(count) = client
        .execute(
            "DELETE FROM challenges WHERE expires > timezone('utc', NOW());",
            &[],
        )
        .await
        .log_error()
    else {
        return;
    };
    if count > 0 {
        tracing::info!("cleaned up {count} challenges");
    }

    let Ok(count) = client
        .execute(
            "DELETE FROM revocations WHERE expires > timezone('utc', NOW());",
            &[],
        )
        .await
        .log_error()
    else {
        return;
    };
    if count > 0 {
        tracing::info!("cleaned up {count} revocations");
    }
}
