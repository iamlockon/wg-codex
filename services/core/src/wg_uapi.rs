use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::{fs, str};

#[derive(Clone)]
pub struct WireGuardUapiClient {
    socket_path: PathBuf,
}

impl WireGuardUapiClient {
    pub fn new(iface: &str) -> Self {
        let socket_path = PathBuf::from(format!("/var/run/wireguard/{iface}.sock"));
        Self { socket_path }
    }

    pub fn set_peer(
        &self,
        public_key: &str,
        allowed_ip: Option<&str>,
        keepalive_secs: Option<u16>,
        remove: bool,
    ) -> Result<(), String> {
        let mut request = String::from("set=1\n");
        request.push_str("public_key=");
        request.push_str(public_key);
        request.push('\n');

        if remove {
            request.push_str("remove=true\n");
        } else {
            request.push_str("replace_allowed_ips=true\n");
            if let Some(allowed_ip) = allowed_ip {
                request.push_str("allowed_ip=");
                request.push_str(allowed_ip);
                request.push('\n');
            }
            if let Some(keepalive) = keepalive_secs {
                request.push_str("persistent_keepalive_interval=");
                request.push_str(&keepalive.to_string());
                request.push('\n');
            }
        }

        request.push('\n');
        self.request(&request)
    }

    pub fn configure_device(&self, private_key_path: &str, listen_port: u16) -> Result<(), String> {
        let key = fs::read_to_string(private_key_path)
            .map_err(|err| format!("read private key failed: {err}"))?;
        let private_key = key.trim();
        if private_key.is_empty() {
            return Err("private key file is empty".to_string());
        }

        let mut request = String::from("set=1\n");
        request.push_str("private_key=");
        request.push_str(private_key);
        request.push('\n');
        request.push_str("listen_port=");
        request.push_str(&listen_port.to_string());
        request.push('\n');
        request.push('\n');
        self.request(&request)
    }

    fn request(&self, request: &str) -> Result<(), String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|err| format!("uapi connect failed: {err}"))?;
        stream
            .write_all(request.as_bytes())
            .map_err(|err| format!("uapi write failed: {err}"))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|err| format!("uapi shutdown failed: {err}"))?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|err| format!("uapi read failed: {err}"))?;

        let errno = response
            .lines()
            .find_map(|line| line.strip_prefix("errno="))
            .ok_or_else(|| format!("uapi missing errno: {response}"))?;
        if errno == "0" {
            Ok(())
        } else {
            Err(format!("uapi errno={errno} response={response}"))
        }
    }
}
