use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

#[derive(Debug)]
pub struct Ipv4Pool {
    base: [u8; 3],
    prefix: u8,
    first_host: u8,
    last_host: u8,
    leased_by_customer: HashMap<Uuid, String>,
    free_hosts: BTreeSet<u8>,
}

impl Ipv4Pool {
    pub fn new(base: [u8; 3], prefix: u8, first_host: u8, last_host: u8) -> Self {
        let mut free_hosts = BTreeSet::new();
        for host in first_host..=last_host {
            free_hosts.insert(host);
        }

        Self {
            base,
            prefix,
            first_host,
            last_host,
            leased_by_customer: HashMap::new(),
            free_hosts,
        }
    }

    pub fn allocate_for(&mut self, customer_id: Uuid) -> Option<String> {
        if let Some(existing) = self.leased_by_customer.get(&customer_id) {
            return Some(existing.clone());
        }

        let host = self.free_hosts.pop_first()?;
        let ip = format!(
            "{}.{}.{}.{}/{}",
            self.base[0], self.base[1], self.base[2], host, self.prefix
        );
        self.leased_by_customer.insert(customer_id, ip.clone());
        Some(ip)
    }

    pub fn release_for(&mut self, customer_id: Uuid) -> bool {
        let Some(leased) = self.leased_by_customer.remove(&customer_id) else {
            return false;
        };

        let host = leased
            .split('/')
            .next()
            .and_then(|v| v.rsplit('.').next())
            .and_then(|v| v.parse::<u8>().ok());

        if let Some(host) = host {
            if host >= self.first_host && host <= self.last_host {
                self.free_hosts.insert(host);
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_and_releases_ip_for_customer() {
        let mut pool = Ipv4Pool::new([10, 90, 0], 24, 2, 3);
        let c1 = Uuid::new_v4();
        let c2 = Uuid::new_v4();

        let ip1 = pool.allocate_for(c1).expect("ip for c1");
        let ip2 = pool.allocate_for(c2).expect("ip for c2");
        assert_ne!(ip1, ip2);

        assert!(pool.release_for(c1));
        let c3 = Uuid::new_v4();
        let ip3 = pool.allocate_for(c3).expect("ip for c3");
        assert_eq!(ip1, ip3);
    }

    #[test]
    fn reuses_existing_lease_for_same_customer() {
        let mut pool = Ipv4Pool::new([10, 90, 0], 24, 2, 10);
        let c1 = Uuid::new_v4();

        let ip1 = pool.allocate_for(c1).expect("ip1");
        let ip2 = pool.allocate_for(c1).expect("ip2");
        assert_eq!(ip1, ip2);
    }
}
