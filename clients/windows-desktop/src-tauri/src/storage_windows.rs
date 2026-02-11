#![cfg(windows)]

use crate::auth::{AuthState, RuntimeState};
use crate::storage::SecureStorage;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Security::Cryptography::{
    CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData, DATA_BLOB,
};
use windows_sys::Win32::System::Memory::LocalFree;

#[derive(Debug, Clone)]
pub struct DpapiFileSecureStorage {
    path: PathBuf,
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
    access_token_dpapi_hex: String,
}

impl DpapiFileSecureStorage {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
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
        serde_json::from_slice::<PersistedState>(&bytes).context("decode state file failed")
    }

    fn save_state(&self, state: &PersistedState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create state directory failed")?;
        }
        let bytes = serde_json::to_vec_pretty(state).context("encode state file failed")?;
        fs::write(&self.path, bytes).context("write state file failed")
    }
}

impl SecureStorage for DpapiFileSecureStorage {
    fn load_auth_state(&self) -> Result<Option<AuthState>> {
        let state = self.load_state()?;
        let auth = match state.auth {
            None => None,
            Some(auth) => {
                let encrypted = decode_hex(&auth.access_token_dpapi_hex)?;
                let decrypted = dpapi_unprotect(&encrypted)?;
                let access_token =
                    String::from_utf8(decrypted).context("access token utf8 failed")?;
                Some(AuthState {
                    customer_id: auth.customer_id,
                    access_token,
                })
            }
        };
        Ok(auth)
    }

    fn save_auth_state(&self, auth: &AuthState) -> Result<()> {
        let mut state = self.load_state()?;
        let encrypted = dpapi_protect(auth.access_token.as_bytes())?;
        state.version = 1;
        state.auth = Some(PersistedAuthState {
            customer_id: auth.customer_id.clone(),
            access_token_dpapi_hex: encode_hex(&encrypted),
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

fn dpapi_protect(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut in_blob = DATA_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &mut in_blob,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "CryptProtectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let data =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }.to_vec();
    unsafe {
        let _ = LocalFree(out_blob.pbData as isize);
    }
    Ok(data)
}

fn dpapi_unprotect(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut in_blob = DATA_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "CryptUnprotectData failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let data =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }.to_vec();
    unsafe {
        let _ = LocalFree(out_blob.pbData as isize);
    }
    Ok(data)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_digit((b >> 4) & 0x0f));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("invalid hex length")
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
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
