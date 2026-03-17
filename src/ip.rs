use std::{io::BufRead, net::IpAddr, str::FromStr};

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

pub struct IpMatcher {
    table: IpNetworkTable<()>,
}
impl IpMatcher {
    pub fn from_reader(reader: impl BufRead) -> Result<Self, anyhow::Error> {
        let mut table = IpNetworkTable::new();
        for line in reader.lines() {
            let line = line?;
            let ip = IpNetwork::from_str(&line)?;
            table.insert(ip, ());
        }
        Ok(Self { table })
    }
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.table.longest_match(ip).is_some()
    }
}
