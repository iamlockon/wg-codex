use backend_e2e::oauth_stub::OAuthStubServer;
use backend_e2e::process::BackendStack;
use jsonwebtoken::decode_header;
use serde_json::Value;

#[tokio::test]
async fn oauth_login_session_lifecycle_and_logout_revocation_e2e() {
    panic!("backend e2e harness not implemented");
}

#[tokio::test]
async fn oauth_stub_serves_token_and_jwks() {
    let stub = OAuthStubServer::start("test-client-id".to_string())
        .await
        .expect("stub should start");

    let client = reqwest::Client::new();

    let token_response = client
        .post(format!("{}/token", stub.base_url()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "auth-code"),
            ("client_id", "test-client-id"),
            ("client_secret", "test-client-secret"),
            ("redirect_uri", "http://127.0.0.1/callback"),
            ("code_verifier", "pkce-verifier"),
        ])
        .send()
        .await
        .expect("token response");
    assert!(token_response.status().is_success());

    let token_json: Value = token_response.json().await.expect("token json");
    let id_token = token_json["id_token"]
        .as_str()
        .expect("id_token should be present");
    let header = decode_header(id_token).expect("header should decode");
    assert_eq!(header.kid.as_deref(), Some(stub.key_id()));

    let jwks_response = client
        .get(format!("{}/jwks", stub.base_url()))
        .send()
        .await
        .expect("jwks response");
    assert!(jwks_response.status().is_success());

    let jwks_json: Value = jwks_response.json().await.expect("jwks json");
    let keys = jwks_json["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"].as_str(), Some(stub.key_id()));
    assert!(keys[0]["n"].as_str().is_some());
    assert!(keys[0]["e"].as_str().is_some());
}

#[tokio::test]
async fn stack_starts_and_entry_healthz_recovers() {
    let stack = BackendStack::start()
        .await
        .expect("backend stack should start");

    let response = reqwest::get(format!("{}/healthz", stack.entry_base_url()))
        .await
        .expect("healthz request");
    assert!(response.status().is_success());
}
