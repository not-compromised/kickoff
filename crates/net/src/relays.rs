//! Relay destinations and their trusted TLS configuration, chosen by the
//! application before binding an endpoint. Peer messages can select only a
//! destination already in this map and cannot supply CA roots.

use iroh::RelayMap;
use iroh::tls::CaTlsConfig;

#[derive(Debug, Clone)]
pub struct Relays {
    pub(crate) map: RelayMap,
    pub(crate) tls: CaTlsConfig,
}

impl Relays {
    pub fn new(map: RelayMap) -> Self {
        Self {
            map,
            tls: CaTlsConfig::default(),
        }
    }

    /// A trusted adapter's explicit TLS roots, such as a local relay fixture's CA.
    pub fn with_ca(map: RelayMap, tls: CaTlsConfig) -> Self {
        Self { map, tls }
    }
}

impl From<&RelayMap> for Relays {
    fn from(map: &RelayMap) -> Self {
        Self::new(map.clone())
    }
}

impl From<&Relays> for Relays {
    fn from(relays: &Relays) -> Self {
        relays.clone()
    }
}
