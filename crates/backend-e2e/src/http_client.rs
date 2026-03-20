use anyhow::{Context, anyhow};
use reqwest::StatusCode;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

#[derive(Clone)]
pub struct BackendApiClient {
    base_url: String,
    http: reqwest::Client,
}

impl BackendApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            http: reqwest::Client::new(),
        }
    }

    pub async fn oauth_callback(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> anyhow::Result<OAuthCallbackResponse> {
        self.send_json(
            self.http
                .post(format!("{}/v1/auth/oauth/google/callback", self.base_url))
                .json(&serde_json::json!({
                    "code": code,
                    "code_verifier": code_verifier,
                    "nonce": nonce,
                })),
            StatusCode::OK,
        )
        .await
    }

    pub async fn upsert_subscription(
        &self,
        customer_id: Uuid,
        plan_code: &str,
        status: &str,
    ) -> anyhow::Result<UpsertSubscriptionResponse> {
        self.send_json(
            self.http
                .post(format!("{}/v1/admin/subscriptions", self.base_url))
                .header("x-admin-token", "admin-secret")
                .json(&serde_json::json!({
                    "customer_id": customer_id,
                    "plan_code": plan_code,
                    "status": status,
                })),
            StatusCode::OK,
        )
        .await
    }

    pub async fn register_device(
        &self,
        access_token: &str,
        name: &str,
        public_key: &str,
    ) -> anyhow::Result<DeviceResponse> {
        self.send_json(
            self.http
                .post(format!("{}/v1/devices", self.base_url))
                .bearer_auth(access_token)
                .json(&serde_json::json!({
                    "name": name,
                    "public_key": public_key,
                })),
            StatusCode::OK,
        )
        .await
    }

    pub async fn start_session(
        &self,
        access_token: &str,
        device_id: Uuid,
        region: &str,
    ) -> anyhow::Result<StartSessionResponse> {
        self.start_session_with_reconnect(access_token, device_id, region, None)
            .await
    }

    pub async fn start_session_with_reconnect(
        &self,
        access_token: &str,
        device_id: Uuid,
        region: &str,
        reconnect_session_key: Option<&str>,
    ) -> anyhow::Result<StartSessionResponse> {
        self.send_json(
            self.http
                .post(format!("{}/v1/sessions/start", self.base_url))
                .bearer_auth(access_token)
                .json(&serde_json::json!({
                    "device_id": device_id,
                    "region": region,
                    "reconnect_session_key": reconnect_session_key,
                })),
            StatusCode::OK,
        )
        .await
    }

    pub async fn current_session(
        &self,
        access_token: &str,
    ) -> anyhow::Result<CurrentSessionResponse> {
        self.send_json(
            self.http
                .get(format!("{}/v1/sessions/current", self.base_url))
                .bearer_auth(access_token),
            StatusCode::OK,
        )
        .await
    }

    pub async fn terminate_session(
        &self,
        access_token: &str,
        session_key: &str,
    ) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!(
                "{}/v1/sessions/{session_key}/terminate",
                self.base_url
            ))
            .bearer_auth(access_token)
            .send()
            .await
            .context("terminate session request failed")?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status != StatusCode::NO_CONTENT {
            return Err(anyhow!(
                "unexpected terminate session status {status}: {body}"
            ));
        }
        Ok(())
    }

    pub async fn logout(&self, access_token: &str) -> anyhow::Result<()> {
        let response = self
            .http
            .post(format!("{}/v1/auth/logout", self.base_url))
            .bearer_auth(access_token)
            .send()
            .await
            .context("logout request failed")?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status != StatusCode::NO_CONTENT {
            return Err(anyhow!("unexpected logout status {status}: {body}"));
        }
        Ok(())
    }

    pub async fn list_devices_expect_unauthorized(
        &self,
        access_token: &str,
    ) -> anyhow::Result<ErrorResponse> {
        self.send_json(
            self.http
                .get(format!("{}/v1/devices", self.base_url))
                .bearer_auth(access_token),
            StatusCode::UNAUTHORIZED,
        )
        .await
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        expected_status: StatusCode,
    ) -> anyhow::Result<T> {
        let response = request.send().await.context("request failed")?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status != expected_status {
            return Err(anyhow!("unexpected status {status}: {body}"));
        }
        serde_json::from_str(&body)
            .with_context(|| format!("failed to parse response body: {body}"))
    }
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackResponse {
    pub provider: String,
    pub customer_id: Uuid,
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertSubscriptionResponse {
    pub customer_id: Uuid,
    pub plan_code: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceResponse {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct StartSessionResponse {
    pub status: String,
    pub session_key: Option<String>,
    pub region: Option<String>,
    pub existing_session_key: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CurrentSessionResponse {
    pub active: bool,
    pub session_key: Option<String>,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
