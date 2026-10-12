//! Identity operations. Raw keys and transport-owned copies stay here.

use crate::Secret;
use iroh::endpoint::{Accept, BindError, Builder, ConnectError, Connection};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_base::Signature;
use std::sync::Arc;

/// Shared ownership of one wiping key allocation, never of cloned key bytes.
#[derive(Clone)]
pub struct IdentityKey(Arc<Secret<SecretKey>>);

impl IdentityKey {
    pub fn new(key: SecretKey) -> Self {
        Self(Arc::new(Secret::new(key)))
    }
    pub fn public(&self) -> EndpointId {
        self.0.read(SecretKey::public)
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.read(|key| key.sign(message))
    }
    pub(crate) fn persisted_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        self.0.read(|key| zeroize::Zeroizing::new(key.to_bytes()))
    }
    /// Configure a key-free builder first. The adapter attaches the key only
    /// when binding, and never returns iroh's raw-key accessor to the caller.
    pub async fn bind(&self, builder: Builder) -> Result<KeyEndpoint, BindError> {
        let builder = if cfg!(feature = "mutant-si30-key-lookup") {
            builder
        } else {
            builder.clear_address_lookup()
        }
        .keylog(false);
        let builder = self.0.read(|key| builder.secret_key(key.clone()));
        builder.bind().await.map(KeyEndpoint)
    }
}

/// An identity endpoint without iroh's `secret_key()` escape hatch.
#[derive(Clone)]
pub struct KeyEndpoint(Endpoint);

impl KeyEndpoint {
    pub fn id(&self) -> EndpointId {
        self.0.id()
    }
    pub fn addr(&self) -> EndpointAddr {
        self.0.addr()
    }
    pub fn accept(&self) -> Accept<'_> {
        self.0.accept()
    }
    pub async fn connect(
        &self,
        addr: EndpointAddr,
        alpn: &[u8],
    ) -> Result<Connection, ConnectError> {
        self.0.connect(addr, alpn).await
    }
    pub async fn close(&self) {
        self.0.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::address_lookup::{AddressLookup, AddressLookupBuilder, AddressLookupBuilderError};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug)]
    struct MaliciousLookup(Arc<AtomicBool>);
    impl AddressLookupBuilder for MaliciousLookup {
        fn into_address_lookup(
            self,
            endpoint: &Endpoint,
        ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
            let _stolen = endpoint.secret_key().clone();
            self.0.store(true, Ordering::SeqCst);
            Ok(iroh::address_lookup::MemoryLookup::new())
        }
    }

    #[tokio::test]
    async fn si_30_identity_adapter_refuses_key_observing_callbacks() {
        let observed = Arc::new(AtomicBool::new(false));
        let key = IdentityKey::new(SecretKey::generate());
        let ep = key
            .bind(
                Endpoint::builder(iroh::endpoint::presets::Minimal)
                    .clear_ip_transports()
                    .relay_mode(iroh::RelayMode::Disabled)
                    .bind_addr("127.0.0.1:0")
                    .unwrap()
                    .address_lookup(MaliciousLookup(Arc::clone(&observed)))
                    .keylog(true),
            )
            .await
            .unwrap();
        assert_eq!(ep.id(), key.public());
        ep.close().await;
        assert!(
            !observed.load(Ordering::SeqCst),
            "caller callback recovered the transport-owned identity key"
        );
    }
}
