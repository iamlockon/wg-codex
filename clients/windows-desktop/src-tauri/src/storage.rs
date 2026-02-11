use crate::auth::{AuthState, RuntimeState};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub trait SecureStorage {
    fn load_auth_state(&self) -> Result<Option<AuthState>>;
    fn save_auth_state(&self, state: &AuthState) -> Result<()>;
    fn clear_auth_state(&self) -> Result<()>;

    fn load_runtime_state(&self) -> Result<RuntimeState>;
    fn save_runtime_state(&self, state: &RuntimeState) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct FileSecureStorage {
    path: PathBuf,
    obfuscation_key: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedState {
    version: u8,
    auth: Option<PersistedAuthState>,
    runtime: RuntimeState,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedAuthState {
    customer_id: String,
    access_token_obfuscated: String,
}

impl FileSecureStorage {
    pub fn new(path: PathBuf, obfuscation_key: String) -> Self {
        Self {
            path,
            obfuscation_key,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load_state(&self) -> Result<PersistedState> {
        if !self.path.exists() {
            return Ok(PersistedState {
                version: 1,
                ..PersistedState::default()
            });
        }
        let bytes = fs::read(&self.path).context("read state file failed")?;
        let state =
            serde_json::from_slice::<PersistedState>(&bytes).context("decode state file failed")?;
        Ok(state)
    }

    fn save_state(&self, state: &PersistedState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create state directory failed")?;
        }
        let data = serde_json::to_vec_pretty(state).context("encode state file failed")?;
        fs::write(&self.path, data).context("write state file failed")?;
        Ok(())
    }

    fn obfuscate(&self, plain: &str) -> String {
        let key = self.obfuscation_key.as_bytes();
        let mut out = String::with_capacity(plain.len() * 2);
        for (i, b) in plain.as_bytes().iter().enumerate() {
            let x = *b ^ key[i % key.len()];
            out.push(hex_digit((x >> 4) & 0x0f));
            out.push(hex_digit(x & 0x0f));
        }
        out
    }

    fn deobfuscate(&self, encoded: &str) -> Result<String> {
        let key = self.obfuscation_key.as_bytes();
        if !encoded.len().is_multiple_of(2) {
            anyhow::bail!("invalid obfuscated token length");
        }
        let mut raw = Vec::with_capacity(encoded.len() / 2);
        let bytes = encoded.as_bytes();
        let mut idx = 0usize;
        while idx < bytes.len() {
            let hi = from_hex(bytes[idx]).context("invalid hex high nibble")?;
            let lo = from_hex(bytes[idx + 1]).context("invalid hex low nibble")?;
            raw.push((hi << 4) | lo);
            idx += 2;
        }
        for (i, b) in raw.iter_mut().enumerate() {
            *b ^= key[i % key.len()];
        }
        String::from_utf8(raw).context("invalid utf8 token")
    }
}

impl SecureStorage for FileSecureStorage {
    fn load_auth_state(&self) -> Result<Option<AuthState>> {
        let state = self.load_state()?;
        let auth = match state.auth {
            None => None,
            Some(auth) => Some(AuthState {
                customer_id: auth.customer_id,
                access_token: self.deobfuscate(&auth.access_token_obfuscated)?,
            }),
        };
        Ok(auth)
    }

    fn save_auth_state(&self, auth: &AuthState) -> Result<()> {
        let mut state = self.load_state()?;
        state.version = 1;
        state.auth = Some(PersistedAuthState {
            customer_id: auth.customer_id.clone(),
            access_token_obfuscated: self.obfuscate(&auth.access_token),
        });
        self.save_state(&state)
    }

    fn clear_auth_state(&self) -> Result<()> {
        let mut state = self.load_state()?;
        state.auth = None;
        self.save_state(&state)
    }

    fn load_runtime_state(&self) -> Result<RuntimeState> {
        let state = self.load_state()?;
        Ok(state.runtime)
    }

    fn save_runtime_state(&self, runtime: &RuntimeState) -> Result<()> {
        let mut state = self.load_state()?;
        state.version = 1;
        state.runtime = runtime.clone();
        self.save_state(&state)
    }
}

fn hex_digit(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        10..=15 => (b'a' + (v - 10)) as char,
        _ => '0',
    }
}

fn from_hex(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn persisted_auth_token_is_not_plaintext() {
        let path = unique_tmp_file("wg-storage");
        let storage = FileSecureStorage::new(path.clone(), "key-123".to_string());
        let auth = AuthState {
            customer_id: "cust-1".to_string(),
            access_token: "secret-token-value".to_string(),
        };
        storage.save_auth_state(&auth).expect("save state");
        let raw = fs::read_to_string(&path).expect("read state file");
        assert!(!raw.contains("secret-token-value"));
        assert!(raw.contains("access_token_obfuscated"));
    }

    fn unique_tmp_file(prefix: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{now}.json"))
    }
}
