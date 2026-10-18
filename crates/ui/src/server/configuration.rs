//! HTTP adapters for configuration controls; the application owns their behavior.
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{UiState, check_origin};
use crate::{ConfigurationError, ConfigurationInput};

fn configuration_error(error: ConfigurationError) -> Response {
    let status = match &error {
        ConfigurationError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        ConfigurationError::NotFound | ConfigurationError::MissingFile(_) => StatusCode::NOT_FOUND,
        ConfigurationError::ReadOnly => StatusCode::FORBIDDEN,
        ConfigurationError::Conflict | ConfigurationError::Busy | ConfigurationError::InUse => {
            StatusCode::CONFLICT
        }
        ConfigurationError::Storage | ConfigurationError::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    (
        status,
        Json(serde_json::json!({"error": error.to_string()})),
    )
        .into_response()
}

pub(super) async fn list_configurations(State(state): State<UiState>) -> Response {
    let Some(control) = &state.configurations else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(_permit) = state.configuration_queries.try_acquire() else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    match control.list().await {
        Ok(list) => Json(list).into_response(),
        Err(error) => configuration_error(error),
    }
}

pub(super) async fn create_configuration(
    State(state): State<UiState>,
    headers: HeaderMap,
    input: Result<Json<ConfigurationInput>, JsonRejection>,
) -> Response {
    save_configuration(state, headers, None, input).await
}

pub(super) async fn update_configuration(
    Path(id): Path<String>,
    State(state): State<UiState>,
    headers: HeaderMap,
    input: Result<Json<ConfigurationInput>, JsonRejection>,
) -> Response {
    save_configuration(state, headers, Some(id), input).await
}

async fn save_configuration(
    state: UiState,
    headers: HeaderMap,
    id: Option<String>,
    input: Result<Json<ConfigurationInput>, JsonRejection>,
) -> Response {
    if let Err(status) = check_origin(&headers) {
        return status.into_response();
    }
    let Some(control) = &state.configurations else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(_permit) = state.configuration_queries.try_acquire() else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Json(input) = match input {
        Ok(input) => input,
        Err(_) => {
            return configuration_error(ConfigurationError::Invalid(
                "Invalid configuration request (maximum 2 MiB)".into(),
            ));
        }
    };
    let creating = id.is_none();
    match control.save(id, input).await {
        Ok(summary) => (
            if creating {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(summary),
        )
            .into_response(),
        Err(error) => configuration_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivateConfiguration {
    revision: u64,
}

pub(super) async fn activate_configuration(
    Path(id): Path<String>,
    State(state): State<UiState>,
    headers: HeaderMap,
    input: Result<Json<ActivateConfiguration>, JsonRejection>,
) -> Response {
    if let Err(status) = check_origin(&headers) {
        return status.into_response();
    }
    let Some(control) = &state.configurations else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(_permit) = state.configuration_queries.try_acquire() else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(Json(input)) = input else {
        return configuration_error(ConfigurationError::Invalid(
            "Invalid activation request".into(),
        ));
    };
    match control.activate(id, input.revision).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(error) => configuration_error(error),
    }
}

pub(super) async fn delete_configuration(
    Path(id): Path<String>,
    State(state): State<UiState>,
    headers: HeaderMap,
    input: Result<Json<ActivateConfiguration>, JsonRejection>,
) -> Response {
    if let Err(status) = check_origin(&headers) {
        return status.into_response();
    }
    let Some(control) = &state.configurations else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(_permit) = state.configuration_queries.try_acquire() else {
        return configuration_error(ConfigurationError::Unavailable);
    };
    let Ok(Json(input)) = input else {
        return configuration_error(ConfigurationError::Invalid(
            "Invalid deletion request".into(),
        ));
    };
    match control.delete(id, input.revision).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => configuration_error(error),
    }
}
