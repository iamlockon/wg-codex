#[cfg(feature = "native-nft")]
use std::process::Command;

#[cfg(feature = "native-nft")]
pub fn ensure_masquerade(egress_iface: &str) -> Result<(), String> {
    if egress_iface.trim().is_empty() {
        return Err("native nft: empty egress interface".to_string());
    }

    run_allow_failure(&["nft", "add", "table", "ip", "nat"]);
    run_allow_failure(&[
        "nft",
        "add",
        "chain",
        "ip",
        "nat",
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "100",
        ";",
        "}",
    ]);

    let chain_text = list_postrouting_chain()?;
    if has_masquerade_rule(&chain_text, egress_iface) {
        return Ok(());
    }

    run(&[
        "nft",
        "add",
        "rule",
        "ip",
        "nat",
        "postrouting",
        "oifname",
        egress_iface,
        "masquerade",
    ])
}

#[cfg(feature = "native-nft")]
fn run(args: &[&str]) -> Result<(), String> {
    let (program, rest) = args
        .split_first()
        .ok_or_else(|| "native nft: empty command".to_string())?;
    let output = Command::new(program)
        .args(rest)
        .output()
        .map_err(|err| format!("native nft: {} exec failed: {err}", program))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "native nft: {} failed with status {}: {}",
            program,
            output.status,
            stderr.trim()
        ))
    }
}

#[cfg(feature = "native-nft")]
fn run_allow_failure(args: &[&str]) {
    let _ = run(args);
}

#[cfg(feature = "native-nft")]
fn list_postrouting_chain() -> Result<String, String> {
    let output = Command::new("nft")
        .args(["list", "chain", "ip", "nat", "postrouting"])
        .output()
        .map_err(|err| format!("native nft: list chain exec failed: {err}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "native nft: list chain failed with status {}: {}",
            output.status,
            stderr.trim()
        ))
    }
}

#[cfg(feature = "native-nft")]
fn has_masquerade_rule(chain_text: &str, egress_iface: &str) -> bool {
    let iface_quoted = format!("oifname \"{egress_iface}\"");
    let iface_unquoted = format!("oifname {egress_iface}");
    chain_text.contains(&iface_quoted) && chain_text.contains("masquerade")
        || chain_text.contains(&iface_unquoted) && chain_text.contains("masquerade")
}

#[cfg(not(feature = "native-nft"))]
pub fn ensure_masquerade(_egress_iface: &str) -> Result<(), String> {
    Err("native nft driver requested, but core was built without feature `native-nft`".to_string())
}

#[cfg(all(test, feature = "native-nft"))]
mod tests {
    use super::*;

    #[test]
    fn has_masquerade_rule_matches_quoted_iface() {
        let text = r#"
chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" masquerade
}
"#;
        assert!(has_masquerade_rule(text, "eth0"));
    }

    #[test]
    fn has_masquerade_rule_matches_unquoted_iface() {
        let text = r#"
chain postrouting {
    oifname ens5 masquerade
}
"#;
        assert!(has_masquerade_rule(text, "ens5"));
    }

    #[test]
    fn has_masquerade_rule_rejects_different_iface() {
        let text = r#"
chain postrouting {
    oifname "eth0" masquerade
}
"#;
        assert!(!has_masquerade_rule(text, "eth1"));
    }
}
