use openssl::{pkey::PKey, x509::X509};

use crate::PushError;

/// Owns a newly-created activation key until its certificate has been
/// validated. Dropping an uncommitted candidate removes only its own alias.
pub(crate) struct CandidateKey<K> {
    key: Option<K>,
    alias: String,
    cleanup: Option<Box<dyn FnOnce(&str) + Send>>,
}

impl<K> CandidateKey<K> {
    pub(crate) fn new(
        key: K,
        alias: String,
        cleanup: impl FnOnce(&str) + Send + 'static,
    ) -> Self {
        Self {
            key: Some(key),
            alias,
            cleanup: Some(Box::new(cleanup)),
        }
    }

    pub(crate) fn key(&self) -> &K {
        self.key.as_ref().expect("candidate key missing")
    }

    pub(crate) fn commit(mut self) -> K {
        self.cleanup = None;
        self.key.take().expect("candidate key missing")
    }
}

impl<K> Drop for CandidateKey<K> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup(&self.alias);
        }
    }
}

/// Compare the returned certificate's public key with the candidate key's
/// public-key DER without exporting or logging either key.
pub(crate) fn validate_certificate_public_key(
    certificate_der: &[u8],
    candidate_public_key_der: &[u8],
) -> Result<(), PushError> {
    let certificate = X509::from_der(certificate_der)?;
    let certificate_key = certificate.public_key()?;
    let candidate_key = PKey::public_key_from_der(candidate_public_key_der)?;
    if !certificate_key.public_eq(&candidate_key) {
        return Err(PushError::AlbertCertParseError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        hash::MessageDigest,
        pkey::{PKey, Private},
        rsa::Rsa,
        x509::{X509, X509Name},
    };
    use std::{
        collections::HashSet,
        future::pending,
        sync::Arc,
        sync::Mutex,
        time::Duration,
    };

    #[derive(Default)]
    struct InMemoryKeys {
        aliases: HashSet<String>,
        destroyed: Vec<String>,
    }

    fn candidate(
        store: Arc<Mutex<InMemoryKeys>>,
        alias: &str,
    ) -> CandidateKey<String> {
        let alias = alias.to_owned();
        store.lock().unwrap().aliases.insert(alias.clone());
        let cleanup_store = store.clone();
        CandidateKey::new(alias.clone(), alias, move |candidate_alias| {
            let mut store = cleanup_store.lock().unwrap();
            store.aliases.remove(candidate_alias);
            store.destroyed.push(candidate_alias.to_owned());
        })
    }

    #[test]
    fn failure_drop_preserves_old_key_and_removes_only_candidate() {
        let store = Arc::new(Mutex::new(InMemoryKeys::default()));
        store
            .lock()
            .unwrap()
            .aliases
            .insert("activation:serial".to_owned());
        {
            let _candidate = candidate(store.clone(), "activation:serial:fresh");
        }
        let store = store.lock().unwrap();
        assert!(store.aliases.contains("activation:serial"));
        assert!(!store.aliases.contains("activation:serial:fresh"));
        assert_eq!(store.destroyed, vec!["activation:serial:fresh".to_owned()]);
    }

    #[test]
    fn commit_keeps_new_key_and_does_not_destroy_it() {
        let store = Arc::new(Mutex::new(InMemoryKeys::default()));
        let key = candidate(store.clone(), "activation:serial:fresh").commit();
        assert_eq!(key, "activation:serial:fresh");
        let store = store.lock().unwrap();
        assert!(store.aliases.contains("activation:serial:fresh"));
        assert!(store.destroyed.is_empty());
    }

    #[tokio::test]
    async fn cancellation_drops_candidate_and_cleans_up() {
        let destroyed = Arc::new(Mutex::new(Vec::new()));
        let cleanup_state = destroyed.clone();
        let future = async move {
            let _candidate = CandidateKey::new(
                "candidate".to_owned(),
                "activation:serial:canceled".to_owned(),
                move |alias| cleanup_state.lock().unwrap().push(alias.to_owned()),
            );
            pending::<()>().await;
        };
        assert!(tokio::time::timeout(Duration::from_millis(20), future)
            .await
            .is_err());
        assert_eq!(
            *destroyed.lock().unwrap(),
            vec!["activation:serial:canceled".to_owned()]
        );
    }

    fn certificate_for(key: &PKey<Private>) -> Vec<u8> {
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "activation-key-lifecycle-test")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(key).unwrap();
        certificate
            .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(key, MessageDigest::sha256()).unwrap();
        certificate.build().to_der().unwrap()
    }

    #[test]
    fn mismatched_certificate_is_refused_without_keystore_access() {
        let candidate_key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let certificate_key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let certificate = certificate_for(&certificate_key);
        let candidate_public_key = candidate_key.public_key_to_der().unwrap();
        assert!(validate_certificate_public_key(&certificate, &candidate_public_key).is_err());
    }

    #[test]
    fn matching_certificate_is_accepted_without_keystore_access() {
        let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let certificate = certificate_for(&key);
        let public_key = key.public_key_to_der().unwrap();
        assert!(validate_certificate_public_key(&certificate, &public_key).is_ok());
    }
}
