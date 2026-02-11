use crate::models::{
    CurrentSessionResponse, Device, OAuthCallbackRequest, OAuthCallbackResponse,
    RegisterDeviceRequest, StartSessionResponse,
};
use anyhow::Context;
use reqwest::StatusCode;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct EntryApi {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartSessionRequest {
    pub device_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconnect_session_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_hint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EntryApiError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("api error status={status} code={code}")]
    Api { status: u16, code: String },
}

#[derive(Debug, serde::Deserialize)]
struct ErrorPayload {
    error: String,
}

impl EntryApi {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn oauth_callback(
        &self,
        provider: &str,
        payload: OAuthCallbackRequest,
    ) -> Result<OAuthCallbackResponse, EntryApiError> {
        self.request_json(
            self.client
                .post(format!(
                    "{}/v1/auth/oauth/{provider}/callback",
                    self.base_url
                ))
                .json(&payload),
            StatusCode::OK,
        )
        .await
    }

    pub async fn logout(&self, access_token: &str) -> Result<(), EntryApiError> {
        let response = self
            .client
            .post(format!("{}/v1/auth/logout", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_transport)?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }
        Err(map_api_error(response).await)
    }

    pub async fn list_devices(&self, access_token: &str) -> Result<Vec<Device>, EntryApiError> {
        self.request_json(
            self.client
                .get(format!("{}/v1/devices", self.base_url))
                .bearer_auth(access_token),
            StatusCode::OK,
        )
        .await
    }

    pub async fn register_device(
        &self,
        access_token: &str,
        payload: RegisterDeviceRequest,
    ) -> Result<Device, EntryApiError> {
        self.request_json(
            self.client
                .post(format!("{}/v1/devices", self.base_url))
                .bearer_auth(access_token)
                .json(&payload),
            StatusCode::OK,
        )
        .await
    }

    pub async fn start_session(
        &self,
        access_token: &str,
        payload: StartSessionRequest,
    ) -> Result<StartSessionResponse, EntryApiError> {
        self.request_json(
            self.client
                .post(format!("{}/v1/sessions/start", self.base_url))
                .bearer_auth(access_token)
                .json(&payload),
            StatusCode::OK,
        )
        .await
    }

    pub async fn terminate_session(
        &self,
        access_token: &str,
        session_key: &str,
    ) -> Result<(), EntryApiError> {
        let response = self
            .client
            .post(format!(
                "{}/v1/sessions/{session_key}/terminate",
                self.base_url
            ))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(map_transport)?;
        if response.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }
        Err(map_api_error(response).await)
    }

    pub async fn current_session(
        &self,
        access_token: &str,
    ) -> Result<CurrentSessionResponse, EntryApiError> {
        self.request_json(
            self.client
                .get(format!("{}/v1/sessions/current", self.base_url))
                .bearer_auth(access_token),
            StatusCode::OK,
        )
        .await
    }

    async fn request_json<T: serde::de::DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<T, EntryApiError> {
        let response = builder.send().await.map_err(map_transport)?;
        if response.status() != expected_status {
            return Err(map_api_error(response).await);
        }
        response
            .json::<T>()
            .await
            .context("decode response failed")
            .map_err(|e| EntryApiError::Decode(e.to_string()))
    }
}

async fn map_api_error(response: reqwest::Response) -> EntryApiError {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let code = serde_json::from_str::<ErrorPayload>(&body)
        .map(|v| v.error)
        .unwrap_or_else(|_| "unknown_error".to_string());
    EntryApiError::Api { status, code }
}

fn map_transport(err: reqwest::Error) -> EntryApiError {
    EntryApiError::Transport(err.to_string())
}
