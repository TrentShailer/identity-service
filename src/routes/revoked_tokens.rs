use core::marker::PhantomData;

use axum::extract::{Path, State};
use http::StatusCode;
use ts_api_helper::{ApiKey, ErrorResponse, InternalServerError};

use crate::{ApiState, sql};

pub async fn get_revoked_token(
    ApiKey(_): ApiKey,
    Path(token): Path<String>,
    State(state): State<ApiState>,
) -> Result<StatusCode, ErrorResponse> {
    let connection = state
        .pool
        .get()
        .await
        .internal_server_error("get db connection")?;

    let row = connection
        .query_opt(
            sql::revocation::get_by_token()[0],
            sql::revocation::GetByTokenParams {
                p1: &token,
                phantom_data: PhantomData,
            }
            .params()
            .as_slice(),
        )
        .await
        .internal_server_error("get revocation by token")?;

    if row.is_some() {
        Ok(StatusCode::OK)
    } else {
        Err(ErrorResponse::not_found::<String>(None))
    }
}
