//! Wire forms of `EndpointAddr`. iroh's own serde form admits custom
//! transports and an unbounded address set, and hands relay text straight to a
//! full URL parser. These forms bound every list, refuse custom transports, and
//! let only plain `https://` relay text reach the parser. Whether a relay or an
//! address is then *used* is `net::egress`'s decision (SI-29).

use std::net::SocketAddr;
use std::str::FromStr;

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, TransportAddr};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{BoundedVec, WireError};

const MAX_RELAYS: usize = 4;
const MAX_IPS: usize = 8;
const MAX_RELAY_URL_LEN: usize = 128;
const RELAY_SCHEME: &str = "https://";

/// A relay URL as text: `https://`, then lowercase ASCII letters, digits and
/// `.-:/` only, in the form the URL parser itself prints.
#[derive(Clone, PartialEq, Eq)]
struct RelayText(RelayUrl);

impl RelayText {
    fn parse(text: &str) -> Result<RelayText, WireError> {
        if text.len() > MAX_RELAY_URL_LEN {
            return Err(WireError::TooLong {
                max: MAX_RELAY_URL_LEN,
            });
        }
        let rest = text
            .strip_prefix(RELAY_SCHEME)
            .ok_or(WireError::Malformed)?;
        let plain = rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:/".contains(&b));
        if rest.is_empty() || !plain {
            return Err(WireError::Malformed);
        }
        let url = RelayUrl::from_str(text).map_err(|_| WireError::Malformed)?;
        if url.to_string() != text {
            return Err(WireError::Malformed);
        }
        Ok(RelayText(url))
    }

    fn from_url(url: &RelayUrl) -> Result<RelayText, WireError> {
        RelayText::parse(&url.to_string())
    }
}

impl Serialize for RelayText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for RelayText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        RelayText::parse(text).map_err(|_| de::Error::custom("invalid relay url"))
    }
}

/// An endpoint address that may carry direct addresses: the host's session
/// endpoint in `Admitted`.
#[derive(Serialize, Deserialize)]
#[serde(rename = "Addr")]
pub(crate) struct AddrRepr {
    id: EndpointId,
    relays: BoundedVec<RelayText, MAX_RELAYS>,
    ips: BoundedVec<SocketAddr, MAX_IPS>,
}

/// A door address: relay-only by construction (§3.4), so a ticket cannot
/// carry a direct address at all.
#[derive(Serialize, Deserialize)]
#[serde(rename = "DoorAddr")]
pub(crate) struct DoorRepr {
    id: EndpointId,
    relays: BoundedVec<RelayText, MAX_RELAYS>,
}

fn split(addr: &EndpointAddr) -> Result<(Vec<RelayText>, Vec<SocketAddr>), WireError> {
    let mut relays = Vec::new();
    let mut ips = Vec::new();
    for transport in &addr.addrs {
        match transport {
            TransportAddr::Relay(url) => relays.push(RelayText::from_url(url)?),
            TransportAddr::Ip(ip) => ips.push(*ip),
            _ => return Err(WireError::Malformed),
        }
    }
    Ok((relays, ips))
}

fn join(
    id: EndpointId,
    relays: &BoundedVec<RelayText, MAX_RELAYS>,
    ips: &[SocketAddr],
) -> EndpointAddr {
    let relays = relays
        .as_slice()
        .iter()
        .map(|r| TransportAddr::Relay(r.0.clone()));
    let ips = ips.iter().map(|ip| TransportAddr::Ip(*ip));
    EndpointAddr::from_parts(id, relays.chain(ips))
}

impl AddrRepr {
    pub(crate) fn from_addr(addr: &EndpointAddr) -> Result<AddrRepr, WireError> {
        let (relays, ips) = split(addr)?;
        Ok(AddrRepr {
            id: addr.id,
            relays: BoundedVec::new(relays)?,
            ips: BoundedVec::new(ips)?,
        })
    }

    pub(crate) fn to_addr(&self) -> EndpointAddr {
        join(self.id, &self.relays, self.ips.as_slice())
    }
}

impl DoorRepr {
    /// Refuses a door with a direct address or with no relay to reach it by.
    pub(crate) fn from_addr(addr: &EndpointAddr) -> Result<DoorRepr, WireError> {
        let (relays, ips) = split(addr)?;
        if !ips.is_empty() || relays.is_empty() {
            return Err(WireError::Malformed);
        }
        Ok(DoorRepr {
            id: addr.id,
            relays: BoundedVec::new(relays)?,
        })
    }

    pub(crate) fn to_addr(&self) -> Result<EndpointAddr, WireError> {
        if self.relays.as_slice().is_empty() {
            return Err(WireError::Malformed);
        }
        Ok(join(self.id, &self.relays, &[]))
    }
}

/// `#[serde(with = "addr::session")]` for an `EndpointAddr` field.
pub(crate) mod session {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        addr: &EndpointAddr,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        AddrRepr::from_addr(addr)
            .map_err(|_| serde::ser::Error::custom("unencodable endpoint address"))?
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EndpointAddr, D::Error> {
        Ok(AddrRepr::deserialize(deserializer)?.to_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_text_accepts_only_plain_canonical_https() {
        assert!(RelayText::parse("https://use1-1.relay.n0.iroh.link./").is_ok());
        assert!(RelayText::parse("https://relay.example.com:8443/").is_ok());
        for bad in [
            "http://relay.example.com/",
            "https://relay.example.com",
            "https://Relay.example.com/",
            "https://user@relay.example.com/",
            "https://relay.example.com/?q",
            "https://relay.example.com/#f",
            "https://",
            "file:///etc/passwd",
            "https://r\u{e9}lay.example.com/",
        ] {
            assert!(RelayText::parse(bad).is_err(), "{bad}");
        }
    }
}
