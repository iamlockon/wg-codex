use base64::Engine as _;
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const WG_GENL_NAME: &str = "wireguard";
const WG_GENL_VERSION: u8 = 1;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_ALLOWEDIPS: u16 = 9;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
const WGPEER_F_HAS_PUBLIC_KEY: u32 = 1 << 2;
const WGPEER_F_HAS_PERSISTENT_KEEPALIVE_INTERVAL: u32 = 1 << 4;

const NLA_F_NESTED: u16 = 1 << 15;

#[repr(C)]
#[derive(Clone, Copy)]
struct GenlMsghdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttrHdr {
    nla_len: u16,
    nla_type: u16,
}

#[derive(Clone)]
pub struct WireGuardUapiClient {
    iface: String,
}

impl WireGuardUapiClient {
    pub fn new(iface: &str) -> Self {
        Self {
            iface: iface.to_string(),
        }
    }

    pub fn set_peer(
        &self,
        public_key: &str,
        allowed_ip: Option<&str>,
        keepalive_secs: Option<u16>,
        remove: bool,
    ) -> Result<(), String> {
        let key = decode_key(public_key)?;

        let mut peer_flags = WGPEER_F_HAS_PUBLIC_KEY;
        if remove {
            peer_flags |= WGPEER_F_REMOVE_ME;
        } else if allowed_ip.is_some() {
            peer_flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
        }
        if keepalive_secs.is_some() {
            peer_flags |= WGPEER_F_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
        }

        let mut peer_payload = Vec::new();
        put_attr(&mut peer_payload, WGPEER_A_PUBLIC_KEY, &key);
        put_attr(&mut peer_payload, WGPEER_A_FLAGS, &peer_flags.to_ne_bytes());

        if let Some(keepalive) = keepalive_secs {
            put_attr(
                &mut peer_payload,
                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                &keepalive.to_ne_bytes(),
            );
        }

        if !remove {
            if let Some(cidr) = allowed_ip {
                let allowedip_payload = build_allowed_ip_attr(cidr)?;
                let mut allowedips = Vec::new();
                put_nested_attr(&mut allowedips, 1, &allowedip_payload);
                put_nested_attr(&mut peer_payload, WGPEER_A_ALLOWEDIPS, &allowedips);
            }
        }

        let mut peers = Vec::new();
        put_nested_attr(&mut peers, 1, &peer_payload);

        let mut attrs = Vec::new();
        put_attr_str(&mut attrs, WGDEVICE_A_IFNAME, &self.iface);
        put_nested_attr(&mut attrs, WGDEVICE_A_PEERS, &peers);

        self.send_wireguard_set(&attrs)
    }

    pub fn configure_device(&self, private_key_path: &str, listen_port: u16) -> Result<(), String> {
        let key_text = fs::read_to_string(private_key_path)
            .map_err(|err| format!("read private key failed: {err}"))?;
        let private_key = decode_key(key_text.trim())?;

        let mut attrs = Vec::new();
        put_attr_str(&mut attrs, WGDEVICE_A_IFNAME, &self.iface);
        put_attr(&mut attrs, WGDEVICE_A_PRIVATE_KEY, &private_key);
        put_attr(
            &mut attrs,
            WGDEVICE_A_LISTEN_PORT,
            &listen_port.to_ne_bytes(),
        );
        self.send_wireguard_set(&attrs)
    }

    pub fn list_peer_public_keys(&self) -> Result<Vec<String>, String> {
        let mut attrs = Vec::new();
        put_attr_str(&mut attrs, WGDEVICE_A_IFNAME, &self.iface);
        let responses = with_netlink(|nl| {
            let family_id = nl.resolve_family_id(WG_GENL_NAME)?;
            nl.send_genl(
                family_id,
                WG_CMD_GET_DEVICE,
                libc::NLM_F_REQUEST as u16 | libc::NLM_F_DUMP as u16,
                &attrs,
            )?;
            nl.recv_genl_messages(family_id)
        })?;

        let mut out = Vec::new();
        for payload in responses {
            for attr in parse_attrs(&payload) {
                if attr.attr_type == WGDEVICE_A_PEERS {
                    for peer in parse_attrs(attr.payload) {
                        for peer_attr in parse_attrs(peer.payload) {
                            if peer_attr.attr_type == WGPEER_A_PUBLIC_KEY {
                                out.push(encode_key(peer_attr.payload));
                            }
                        }
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn send_wireguard_set(&self, attrs: &[u8]) -> Result<(), String> {
        with_netlink(|nl| {
            let family_id = nl.resolve_family_id(WG_GENL_NAME)?;
            nl.send_genl(
                family_id,
                WG_CMD_SET_DEVICE,
                libc::NLM_F_REQUEST as u16 | libc::NLM_F_ACK as u16,
                attrs,
            )?;
            nl.recv_ack()?;
            Ok(())
        })
    }
}

fn with_netlink<T>(f: impl FnOnce(&mut NetlinkConn) -> io::Result<T>) -> Result<T, String> {
    let mut nl = NetlinkConn::new().map_err(|err| format!("netlink open failed: {err}"))?;
    f(&mut nl).map_err(|err| format!("netlink request failed: {err}"))
}

struct NetlinkConn {
    fd: OwnedFd,
    seq: u32,
}

impl NetlinkConn {
    fn new() -> io::Result<Self> {
        let raw_fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, seq: 1 })
    }

    fn resolve_family_id(&mut self, family_name: &str) -> io::Result<u16> {
        let mut attrs = Vec::new();
        put_attr_str(&mut attrs, CTRL_ATTR_FAMILY_NAME, family_name);
        self.send_genl(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            libc::NLM_F_REQUEST as u16,
            &attrs,
        )?;
        let responses = self.recv_genl_messages(GENL_ID_CTRL)?;
        for payload in responses {
            for attr in parse_attrs(&payload) {
                if attr.attr_type == CTRL_ATTR_FAMILY_ID && attr.payload.len() >= 2 {
                    return Ok(u16::from_ne_bytes([attr.payload[0], attr.payload[1]]));
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("generic netlink family {family_name} not found"),
        ))
    }

    fn send_genl(&mut self, nlmsg_type: u16, cmd: u8, flags: u16, attrs: &[u8]) -> io::Result<()> {
        let genl_hdr = GenlMsghdr {
            cmd,
            version: WG_GENL_VERSION,
            reserved: 0,
        };
        let mut payload = Vec::with_capacity(size_of::<GenlMsghdr>() + attrs.len());
        payload.extend_from_slice(as_bytes(&genl_hdr));
        payload.extend_from_slice(attrs);
        self.send_netlink(nlmsg_type, flags, &payload)
    }

    fn send_netlink(&mut self, nlmsg_type: u16, flags: u16, payload: &[u8]) -> io::Result<()> {
        let total_len = (size_of::<libc::nlmsghdr>() + payload.len()) as u32;
        let hdr = libc::nlmsghdr {
            nlmsg_len: total_len,
            nlmsg_type,
            nlmsg_flags: flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };
        self.seq = self.seq.wrapping_add(1);

        let mut msg = Vec::with_capacity(total_len as usize);
        msg.extend_from_slice(as_bytes(&hdr));
        msg.extend_from_slice(payload);

        let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv_ack(&mut self) -> io::Result<()> {
        loop {
            let messages = self.recv_messages()?;
            for msg in messages {
                if msg.msg_type == libc::NLMSG_ERROR as u16 {
                    if msg.payload.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let errno = i32::from_ne_bytes([
                        msg.payload[0],
                        msg.payload[1],
                        msg.payload[2],
                        msg.payload[3],
                    ]);
                    if errno == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-errno));
                }
            }
        }
    }

    fn recv_genl_messages(&mut self, expected_type: u16) -> io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            let messages = self.recv_messages()?;
            let mut saw_done = false;
            let mut saw_multi = false;
            for msg in messages {
                if msg.msg_type == libc::NLMSG_DONE as u16 {
                    saw_done = true;
                    continue;
                }
                if msg.msg_type == libc::NLMSG_ERROR as u16 {
                    if msg.payload.len() < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "short NLMSG_ERROR",
                        ));
                    }
                    let errno = i32::from_ne_bytes([
                        msg.payload[0],
                        msg.payload[1],
                        msg.payload[2],
                        msg.payload[3],
                    ]);
                    if errno != 0 {
                        return Err(io::Error::from_raw_os_error(-errno));
                    }
                    continue;
                }
                if msg.msg_type != expected_type {
                    continue;
                }
                if msg.payload.len() < size_of::<GenlMsghdr>() {
                    continue;
                }
                if (msg.flags & libc::NLM_F_MULTI as u16) != 0 {
                    saw_multi = true;
                }
                out.push(msg.payload[size_of::<GenlMsghdr>()..].to_vec());
            }
            if saw_done || (!saw_multi && !out.is_empty()) {
                return Ok(out);
            }
        }
    }

    fn recv_messages(&mut self) -> io::Result<Vec<NetlinkMessage>> {
        let mut buf = vec![0u8; 65536];
        let len = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = len as usize;
        let mut cursor = 0usize;
        let mut out = Vec::new();
        while cursor + size_of::<libc::nlmsghdr>() <= len {
            let hdr = unsafe { read_unaligned::<libc::nlmsghdr>(&buf[cursor..]) };
            if hdr.nlmsg_len == 0 {
                break;
            }
            let msg_len = hdr.nlmsg_len as usize;
            if cursor + msg_len > len || msg_len < size_of::<libc::nlmsghdr>() {
                break;
            }
            let payload_start = cursor + size_of::<libc::nlmsghdr>();
            let payload_end = cursor + msg_len;
            out.push(NetlinkMessage {
                msg_type: hdr.nlmsg_type,
                flags: hdr.nlmsg_flags,
                payload: buf[payload_start..payload_end].to_vec(),
            });
            cursor += align4(msg_len);
        }
        Ok(out)
    }
}

struct NetlinkMessage {
    msg_type: u16,
    flags: u16,
    payload: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ParsedAttr<'a> {
    attr_type: u16,
    payload: &'a [u8],
}

fn parse_attrs(mut data: &[u8]) -> Vec<ParsedAttr<'_>> {
    let mut out = Vec::new();
    while data.len() >= size_of::<NlAttrHdr>() {
        let hdr = unsafe { read_unaligned::<NlAttrHdr>(data) };
        let attr_len = hdr.nla_len as usize;
        if attr_len < size_of::<NlAttrHdr>() || attr_len > data.len() {
            break;
        }
        let payload = &data[size_of::<NlAttrHdr>()..attr_len];
        out.push(ParsedAttr {
            attr_type: hdr.nla_type & !NLA_F_NESTED,
            payload,
        });
        let next = align4(attr_len);
        if next >= data.len() {
            break;
        }
        data = &data[next..];
    }
    out
}

fn build_allowed_ip_attr(cidr: &str) -> Result<Vec<u8>, String> {
    let (ip_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid allowed_ip cidr: {cidr}"))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|err| format!("invalid allowed_ip ip: {err}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|err| format!("invalid allowed_ip prefix: {err}"))?;

    let mut out = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            put_attr(
                &mut out,
                WGALLOWEDIP_A_FAMILY,
                &(libc::AF_INET as u16).to_ne_bytes(),
            );
            put_attr(&mut out, WGALLOWEDIP_A_IPADDR, &v4.octets());
        }
        IpAddr::V6(v6) => {
            put_attr(
                &mut out,
                WGALLOWEDIP_A_FAMILY,
                &(libc::AF_INET6 as u16).to_ne_bytes(),
            );
            put_attr(&mut out, WGALLOWEDIP_A_IPADDR, &v6.octets());
        }
    }
    put_attr(&mut out, WGALLOWEDIP_A_CIDR_MASK, &[prefix]);
    Ok(out)
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|err| format!("invalid base64 key: {err}"))?;
    if raw.len() != 32 {
        return Err(format!("invalid key length {}, expected 32", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn encode_key(raw: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw)
}

fn put_attr_str(buf: &mut Vec<u8>, attr_type: u16, value: &str) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    put_attr(buf, attr_type, &bytes);
}

fn put_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = (size_of::<NlAttrHdr>() + payload.len()) as u16;
    let hdr = NlAttrHdr {
        nla_len: len,
        nla_type: attr_type,
    };
    buf.extend_from_slice(as_bytes(&hdr));
    buf.extend_from_slice(payload);
    let pad = align4(len as usize) - len as usize;
    if pad > 0 {
        buf.extend(std::iter::repeat_n(0u8, pad));
    }
}

fn put_nested_attr(buf: &mut Vec<u8>, attr_type: u16, nested_payload: &[u8]) {
    put_attr(buf, attr_type | NLA_F_NESTED, nested_payload);
}

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

unsafe fn read_unaligned<T: Copy>(data: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<T>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_peer_public_keys_extracts_all_peers() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let mut peer1 = Vec::new();
        put_attr(&mut peer1, WGPEER_A_PUBLIC_KEY, &key1);
        let mut peer2 = Vec::new();
        put_attr(&mut peer2, WGPEER_A_PUBLIC_KEY, &key2);
        let mut peers = Vec::new();
        put_nested_attr(&mut peers, 1, &peer1);
        put_nested_attr(&mut peers, 2, &peer2);

        let mut payload = Vec::new();
        put_nested_attr(&mut payload, WGDEVICE_A_PEERS, &peers);

        let mut extracted = Vec::new();
        for attr in parse_attrs(&payload) {
            if attr.attr_type == WGDEVICE_A_PEERS {
                for peer in parse_attrs(attr.payload) {
                    for peer_attr in parse_attrs(peer.payload) {
                        if peer_attr.attr_type == WGPEER_A_PUBLIC_KEY {
                            extracted.push(encode_key(peer_attr.payload));
                        }
                    }
                }
            }
        }
        assert_eq!(extracted.len(), 2);
        assert!(extracted.contains(&encode_key(&key1)));
        assert!(extracted.contains(&encode_key(&key2)));
    }
}
