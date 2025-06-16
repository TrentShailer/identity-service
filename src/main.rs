use api_helper::setup_connection_pool;
use axum::{Router, routing::post};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod identity;
mod routes;
mod sql;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = setup_connection_pool("").await.unwrap(); // TODO

    // Migrate database
    {
        let connection = pool.get().await.unwrap(); // TODO
        for migration in sql::migrations::migrate() {
            connection.execute(migration, &[]).await.unwrap(); // TODO
        }
    }

    let app = Router::new()
        .route("/", post(routes::post_identity))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}
