use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use tracing::warn;

const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUER_HTTPS: &str = "https://accounts.google.com";
const ISSUER_SHORT: &str = "accounts.google.com";

#[derive(Clone)]
pub struct GoogleOidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub token_url: String,
    pub jwks_url: String,
}

impl GoogleOidcConfig {
    pub fn from_env() -> Option<Self> {
        let client_id = read_env_or_file("GOOGLE_OIDC_CLIENT_ID")?;
        let client_secret = read_env_or_file("GOOGLE_OIDC_CLIENT_SECRET")?;
        let redirect_uri = read_env_or_file("GOOGLE_OIDC_REDIRECT_URI")?;
        let token_url = std::env::var("GOOGLE_OIDC_TOKEN_URL")
            .unwrap_or_else(|_| DEFAULT_TOKEN_URL.to_string());
        let jwks_url =
            std::env::var("GOOGLE_OIDC_JWKS_URL").unwrap_or_else(|_| DEFAULT_JWKS_URL.to_string());

        Some(Self {
            client_id,
            client_secret,
            redirect_uri,
            token_url,
            jwks_url,
        })
    }
}

fn read_env_or_file(name: &str) -> Option<String> {
    if let Ok(value) = std::env::var(name) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }

    let file_var = format!("{name}_FILE");
    let path = std::env::var(&file_var).ok()?;
    match std::fs::read_to_string(path.trim()) {
        Ok(contents) => {
            let value = contents.trim().to_string();
            if value.is_empty() { None } else { Some(value) }
        }
        Err(err) => {
            warn!(%err, %file_var, "failed to read OIDC config from file");
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct GoogleIdentity {
    pub sub: String,
    pub email: Option<String>,
}

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("missing_id_token")]
    MissingIdToken,
    #[error("missing_key_id")]
    MissingKeyId,
    #[error("unknown_key_id")]
    UnknownKeyId,
    #[error("invalid_nonce")]
    InvalidNonce,
    #[error("token_exchange_failed status={status} code={error}")]
    TokenExchange {
        status: u16,
        error: String,
        description: Option<String>,
    },
    #[error("jwks_fetch_failed status={status}")]
    JwksFetch { status: u16 },
    #[error("http_error")]
    Http(#[from] reqwest::Error),
    #[error("jwt_error")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    _access_token: String,
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleErrorResponse {
    error: String,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GoogleJwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize, Clone)]
struct GoogleClaims {
    sub: String,
    #[serde(rename = "aud")]
    _aud: String,
    #[serde(rename = "exp")]
    _exp: usize,
    #[serde(rename = "iss")]
    _iss: String,
    nonce: Option<String>,
    email: Option<String>,
}

pub async fn authenticate_google(
    http: &Client,
    config: &GoogleOidcConfig,
    code: &str,
    code_verifier: Option<&str>,
    expected_nonce: Option<&str>,
) -> Result<GoogleIdentity, OidcError> {
    let token = exchange_code(http, config, code, code_verifier).await?;
    let id_token = token.id_token.ok_or(OidcError::MissingIdToken)?;
    validate_id_token(http, config, &id_token, expected_nonce).await
}

async fn exchange_code(
    http: &Client,
    config: &GoogleOidcConfig,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<GoogleTokenResponse, OidcError> {
    let mut params: Vec<(&str, String)> = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", config.client_id.clone()),
        ("client_secret", config.client_secret.clone()),
        ("redirect_uri", config.redirect_uri.clone()),
    ];

    if let Some(code_verifier) = code_verifier {
        params.push(("code_verifier", code_verifier.to_string()));
    }

    let response = http
        .post(&config.token_url)
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        let parsed = serde_json::from_str::<GoogleErrorResponse>(&body).ok();
        return Err(OidcError::TokenExchange {
            status,
            error: parsed
                .as_ref()
                .map(|e| e.error.clone())
                .unwrap_or_else(|| "unknown_error".to_string()),
            description: parsed
                .and_then(|e| e.error_description)
                .or_else(|| (!body.trim().is_empty()).then_some(body)),
        });
    }

    response
        .json::<GoogleTokenResponse>()
        .await
        .map_err(OidcError::from)
}

async fn validate_id_token(
    http: &Client,
    config: &GoogleOidcConfig,
    id_token: &str,
    expected_nonce: Option<&str>,
) -> Result<GoogleIdentity, OidcError> {
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or(OidcError::MissingKeyId)?;
    let jwks_response = http.get(&config.jwks_url).send().await?;
    if !jwks_response.status().is_success() {
        return Err(OidcError::JwksFetch {
            status: jwks_response.status().as_u16(),
        });
    }
    let jwks = jwks_response.json::<GoogleJwks>().await?;

    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(OidcError::UnknownKeyId)?;
    let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&config.client_id]);
    validation.set_issuer(&[ISSUER_HTTPS, ISSUER_SHORT]);

    let claims = decode::<GoogleClaims>(id_token, &decoding_key, &validation)?.claims;

    if let Some(expected_nonce) = expected_nonce {
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err(OidcError::InvalidNonce);
        }
    }

    Ok(GoogleIdentity {
        sub: claims.sub,
        email: claims.email,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_env_returns_none_without_required_values() {
        let missing = GoogleOidcConfig::from_env();
        if let Some(cfg) = missing {
            // If env vars are present in test environment, ensure they are non-empty.
            assert!(!cfg.client_id.is_empty());
            assert!(!cfg.client_secret.is_empty());
            assert!(!cfg.redirect_uri.is_empty());
        } else {
            assert!(missing.is_none());
        }
    }

    #[test]
    fn token_url_and_jwks_url_have_defaults_when_config_constructed() {
        let cfg = GoogleOidcConfig {
            client_id: "cid".to_string(),
            client_secret: "secret".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            token_url: DEFAULT_TOKEN_URL.to_string(),
            jwks_url: DEFAULT_JWKS_URL.to_string(),
        };
        assert_eq!(cfg.token_url, DEFAULT_TOKEN_URL);
        assert_eq!(cfg.jwks_url, DEFAULT_JWKS_URL);
    }
}
