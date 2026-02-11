#[cfg(feature = "native-nft")]
pub fn ensure_masquerade(_egress_iface: &str) -> Result<(), String> {
    // Placeholder for forthcoming netlink-native nftables programming path.
    // The runtime wiring already supports selecting this driver explicitly via WG_NAT_DRIVER.
    Err(
        "native nft driver selected, but netlink nftables implementation is not wired yet"
            .to_string(),
    )
}

#[cfg(not(feature = "native-nft"))]
pub fn ensure_masquerade(_egress_iface: &str) -> Result<(), String> {
    Err("native nft driver requested, but core was built without feature `native-nft`".to_string())
}
