#[cfg(feature = "native-nft")]
use nftnl::{
    Batch, Chain, ChainType, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
};
#[cfg(feature = "native-nft")]
use std::ffi::CString;
#[cfg(feature = "native-nft")]
use std::fs;
#[cfg(feature = "native-nft")]
use std::io;

#[cfg(feature = "native-nft")]
const TABLE_NAME: &str = "wg_core_nat";
#[cfg(feature = "native-nft")]
const CHAIN_NAME: &str = "wg_core_postrouting";

#[cfg(feature = "native-nft")]
pub fn ensure_masquerade(egress_iface: &str) -> Result<(), String> {
    let iface = egress_iface.trim();
    if iface.is_empty() {
        return Err("native nft: empty egress interface".to_string());
    }

    let iface_index = read_iface_index(iface)?;
    ensure_table()?;
    reset_chain()?;
    ensure_rule(iface_index)
}

#[cfg(feature = "native-nft")]
fn ensure_table() -> Result<(), String> {
    let table_name = cstring(TABLE_NAME)?;
    let mut batch = Batch::new();
    let table = Table::new(&table_name, ProtoFamily::Ipv4);
    batch.add(&table, MsgType::Add);

    send_batch(batch).or_else(ignore_errno(libc::EEXIST))
}

#[cfg(feature = "native-nft")]
fn reset_chain() -> Result<(), String> {
    let table_name = cstring(TABLE_NAME)?;
    let chain_name = cstring(CHAIN_NAME)?;

    let table = Table::new(&table_name, ProtoFamily::Ipv4);

    // Recreate chain to keep rule set deterministic across restarts.
    let mut delete_batch = Batch::new();
    let delete_chain = Chain::new(&chain_name, &table);
    delete_batch.add(&delete_chain, MsgType::Del);
    let _ = send_batch(delete_batch).or_else(ignore_errno(libc::ENOENT));

    let mut add_batch = Batch::new();
    let mut chain = Chain::new(&chain_name, &table);
    chain.set_type(ChainType::Nat);
    chain.set_hook(Hook::PostRouting, 100);
    chain.set_policy(Policy::Accept);
    add_batch.add(&chain, MsgType::Add);
    send_batch(add_batch)
}

#[cfg(feature = "native-nft")]
fn ensure_rule(iface_index: u32) -> Result<(), String> {
    let table_name = cstring(TABLE_NAME)?;
    let chain_name = cstring(CHAIN_NAME)?;

    let table = Table::new(&table_name, ProtoFamily::Ipv4);
    let chain = Chain::new(&chain_name, &table);

    let mut batch = Batch::new();
    let mut rule = Rule::new(&chain);
    rule.add_expr(&nftnl::nft_expr!(meta oif));
    rule.add_expr(&nftnl::nft_expr!(cmp == iface_index));
    rule.add_expr(&nftnl::nft_expr!(masquerade));
    batch.add(&rule, MsgType::Add);

    send_batch(batch)
}

#[cfg(feature = "native-nft")]
fn read_iface_index(iface: &str) -> Result<u32, String> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let text = fs::read_to_string(&path)
        .map_err(|err| format!("native nft: failed to read {path}: {err}"))?;
    text.trim()
        .parse::<u32>()
        .map_err(|err| format!("native nft: invalid ifindex in {path}: {err}"))
}

#[cfg(feature = "native-nft")]
fn cstring(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("native nft: value contains NUL: {value}"))
}

#[cfg(feature = "native-nft")]
fn send_batch(batch: Batch) -> Result<(), String> {
    let finalized = batch.finalize();
    send_and_process(&finalized).map_err(|err| format!("native nft netlink apply failed: {err}"))
}

#[cfg(feature = "native-nft")]
fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    socket.send_all(batch)?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let seq = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer)? {
        match mnl::cb_run(message, seq, portid)? {
            mnl::CbResult::Stop => break,
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

#[cfg(feature = "native-nft")]
fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "native-nft")]
fn ignore_errno(errno: i32) -> impl FnOnce(String) -> Result<(), String> {
    move |err| {
        let is_expected = err.contains(&format!("os error {errno}"))
            || (errno == libc::EEXIST && err.contains("File exists"))
            || (errno == libc::ENOENT && err.contains("No such file or directory"));
        if is_expected { Ok(()) } else { Err(err) }
    }
}

#[cfg(not(feature = "native-nft"))]
pub fn ensure_masquerade(_egress_iface: &str) -> Result<(), String> {
    Err("native nft driver requested, but core was built without feature `native-nft`".to_string())
}

#[cfg(all(test, feature = "native-nft"))]
mod tests {
    use super::*;

    #[test]
    fn cstring_rejects_nul() {
        let err = cstring("eth0\0bad").expect_err("nul rejected");
        assert!(err.contains("contains NUL"));
    }

    #[test]
    fn iface_index_parse_rejects_missing_iface() {
        let err = read_iface_index("this-iface-should-not-exist").expect_err("missing iface");
        assert!(err.contains("failed to read"));
    }
}
