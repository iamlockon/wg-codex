use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Form, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand::thread_rng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Clone)]
struct OAuthStubState {
    client_id: String,
    key_id: String,
    encoding_key: EncodingKey,
    jwks: serde_json::Value,
}

pub struct OAuthStubServer {
    base_url: String,
    key_id: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl OAuthStubServer {
    pub async fn start(client_id: String) -> anyhow::Result<Self> {
        let mut rng = thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).context("failed to generate RSA private key")?;
        let public_key = RsaPublicKey::from(&private_key);
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .context("failed to encode private key as PEM")?;

        let key_id = "stub-key".to_string();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind OAuth stub listener")?;
        let addr = listener
            .local_addr()
            .context("failed to read OAuth stub local addr")?;

        let state = Arc::new(OAuthStubState {
            client_id,
            key_id: key_id.clone(),
            encoding_key: EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
                .context("failed to build RSA encoding key")?,
            jwks: build_jwks(&key_id, &public_key),
        });

        let app = Router::new()
            .route("/token", post(issue_token))
            .route("/jwks", get(serve_jwks))
            .with_state(state);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(Self {
            base_url: format!("http://{addr}"),
            key_id,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Drop for OAuthStubServer {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

#[derive(Deserialize)]
struct TokenRequest {
    client_id: String,
    code: String,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
}

#[derive(Serialize)]
struct StubClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: usize,
    nonce: Option<String>,
    email: String,
    name: String,
}

async fn issue_token(
    State(state): State<Arc<OAuthStubState>>,
    Form(request): Form<TokenRequest>,
) -> Json<TokenResponse> {
    assert_eq!(request.client_id, state.client_id);
    assert_eq!(request.code, "auth-code");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.key_id.clone());

    let claims = StubClaims {
        iss: "https://accounts.google.com".to_string(),
        aud: state.client_id.clone(),
        sub: "stub-subject".to_string(),
        exp: 4_102_444_800,
        nonce: request.nonce,
        email: "stub@example.com".to_string(),
        name: "Stub User".to_string(),
    };

    let id_token = encode(&header, &claims, &state.encoding_key).expect("token should encode");

    Json(TokenResponse {
        access_token: "stub-access-token".to_string(),
        id_token,
    })
}

async fn serve_jwks(State(state): State<Arc<OAuthStubState>>) -> Json<serde_json::Value> {
    Json(state.jwks.clone())
}

fn build_jwks(key_id: &str, public_key: &RsaPublicKey) -> serde_json::Value {
    let modulus = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let exponent = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": key_id,
            "n": modulus,
            "e": exponent
        }]
    })
}
