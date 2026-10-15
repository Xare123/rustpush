use std::{collections::HashMap, sync::RwLock};

use aes_gcm::{Aes256Gcm, Nonce};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use plist::Data;
use serde::{Deserialize, Serialize};

use crate::{
    EcCurve, EncryptMode, KeyType, Keystore, KeystoreAccessRules, KeystoreDigest, KeystoreError,
    KeystorePadding, LockableKeystore,
    software::{SoftwareKeystoreKey, contained_gcm_decrypt, contained_gcm_encrypt, plist_to_bin},
};

use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;

#[derive(Serialize, Deserialize)]
pub struct BackedUpData {
    public_key: Data,
    ephemeral_key: Data,
    ciphertext: Data,
}

impl BackedUpData {
    fn new(public_key: &[u8], plaintext: &[u8]) -> Result<Self, KeystoreError> {
        let for_key = EcKey::public_key_from_der(&public_key)?;

        let ephermeral_key = EcKey::generate(for_key.group())?;

        let key = PKey::from_ec_key(ephermeral_key)?;
        let pub_key = PKey::from_ec_key(for_key.clone())?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;

        Ok(Self {
            public_key: public_key.to_vec().into(),
            ephemeral_key: key.public_key_to_der()?.into(),
            ciphertext: contained_gcm_encrypt(&secret, plaintext)?.into(),
        })
    }

    fn recover(&self, key: &PKey<Private>) -> Result<Vec<u8>, KeystoreError> {
        let public = EcKey::public_key_from_der(self.ephemeral_key.as_ref())?;

        let my_public = EcKey::public_key_from_der(self.public_key.as_ref())?;
        let my_public = PKey::from_ec_key(my_public)?;
        if !key.public_eq(&my_public) {
            return Err(KeystoreError::KeyUnrecoverable);
        }

        let pub_key = PKey::from_ec_key(public)?;

        let mut deriver = Deriver::new(&key)?;
        deriver.set_peer(&pub_key)?;
        let secret = deriver.derive_to_vec()?;

        Ok(contained_gcm_decrypt(&secret, self.ciphertext.as_ref())?)
    }
}

// backs up private keys with a user authenticated key
#[derive(Serialize, Deserialize)]
pub struct BackupKeystoreState {
    keys: HashMap<String, BackedUpData>,
    secrets: HashMap<String, Data>,
    master_key: Data,
    encrypted_master_key: Data,
}

impl BackupKeystoreState {
    pub fn new(hardware: &impl Keystore) -> Result<(Self, PKey<Private>), KeystoreError> {
        let mut item = Self {
            keys: HashMap::new(),
            secrets: HashMap::new(),
            master_key: Data::new(vec![]),
            encrypted_master_key: Data::new(vec![]),
        };

        let pkey = item.new_master(hardware)?;

        Ok((item, pkey))
    }

    pub fn new_master(&mut self, hardware: &impl Keystore) -> Result<PKey<Private>, KeystoreError> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let master_key = EcKey::generate(&group)?;

        let pkey = PKey::from_ec_key(master_key)?;
        self.update_master(hardware, &pkey)?;

        Ok(pkey)
    }

    pub fn update_master(
        &mut self,
        hardware: &impl Keystore,
        master_key: &PKey<Private>,
    ) -> Result<(), KeystoreError> {
        hardware.overwrite_new(
            "keystore:recovery:master",
            KeyType::Rsa(2048),
            KeystoreAccessRules {
                encryption_paddings: vec![KeystorePadding::OAEP {
                    md: KeystoreDigest::Sha256,
                    mgf1: KeystoreDigest::Sha1,
                }],
                digests: vec![KeystoreDigest::Sha256],
                mgf1_digests: vec![KeystoreDigest::Sha1],
                block_modes: vec![EncryptMode::Rsa(crate::KeystorePadding::OAEP {
                    md: KeystoreDigest::Sha256,
                    mgf1: KeystoreDigest::Sha1,
                })],
                require_user: true,
                can_decrypt: true,
                can_encrypt: true,
                ..Default::default()
            },
        )?;

        let key = master_key.private_key_to_der()?;
        let ciphertext = hardware.encrypt(
            "keystore:recovery:master",
            &key,
            &mut EncryptMode::Rsa(crate::KeystorePadding::OAEP {
                md: KeystoreDigest::Sha256,
                mgf1: KeystoreDigest::Sha1,
            }),
        )?;

        self.master_key = master_key.public_key_to_der()?.into();
        self.encrypted_master_key = ciphertext.into();
        Ok(())
    }
}

pub struct BackupKeystore<T> {
    pub state: RwLock<BackupKeystoreState>,
    pub update_state: Box<dyn Fn(&BackupKeystoreState) + Send + Sync>,
    pub hardware: T,
    pub unlocked_key: RwLock<Option<PKey<Private>>>,
}

impl<T: Keystore> BackupKeystore<T> {
    fn get_priv_key(&self, alias: &str) -> Result<SoftwareKeystoreKey, KeystoreError> {
        let state = self.state.read().expect("Failed to read!");
        let key = state.keys.get(alias).ok_or(KeystoreError::KeyNotFound)?;

        let unlocked_key = self.unlocked_key.read().unwrap();
        let recovery_key = unlocked_key.as_ref().ok_or(KeystoreError::KeystoreLocked)?;
        let cipher = key.recover(recovery_key)?;
        Ok(plist::from_bytes(&cipher).expect("Failed to decrypt!"))
    }

    fn import_new_key(
        &self,
        alias: &str,
        key: SoftwareKeystoreKey,
        r#type: KeyType,
        priv_key: &[u8],
        access_rules: KeystoreAccessRules,
    ) -> Result<(), KeystoreError> {
        // Serialize create/import through publication, including the hardware alias check.
        let mut state = self.state.write().expect("Failed to read!");
        if state.keys.contains_key(alias)
            || self
                .hardware
                .list_keys()?
                .iter()
                .any(|existing| existing == alias)
        {
            return Err(KeystoreError::KeyAlreadyExists);
        }

        let encoded = plist_to_bin(&key).map_err(|_| {
            KeystoreError::KeystoreError("Failed to encode backup key entry".to_string())
        })?;
        let backup = BackedUpData::new(state.master_key.as_ref(), &encoded)?;
        self.hardware
            .import_key(alias, r#type, priv_key, access_rules)?;

        // All fallible preparation precedes import. The callback has no Result, so a
        // callback panic or process crash after import remains outside this guarantee.
        state.keys.insert(alias.to_string(), backup);
        (self.update_state)(&*state);
        Ok(())
    }
}

impl<T: Keystore> LockableKeystore for BackupKeystore<T> {
    fn unlock(&self) -> Result<(), KeystoreError> {
        let state = self.state.read().expect("Failed to read!");

        let decrypt = self.hardware.decrypt(
            "keystore:recovery:master",
            state.encrypted_master_key.as_ref(),
            &EncryptMode::Rsa(crate::KeystorePadding::OAEP {
                md: KeystoreDigest::Sha256,
                mgf1: KeystoreDigest::Sha1,
            }),
        )?;
        *self.unlocked_key.write().unwrap() =
            Some(PKey::from_ec_key(EcKey::private_key_from_der(&decrypt)?)?);
        Ok(())
    }

    fn lock(&self) -> Result<(), KeystoreError> {
        *self.unlocked_key.write().unwrap() = None;
        Ok(())
    }

    fn is_locked(&self) -> bool {
        self.unlocked_key.read().unwrap().is_none()
    }

    // recover after our master key is pulled from under our feet
    fn recover(&self) -> Result<(), KeystoreError> {
        let mut state = self.state.write().unwrap();
        let unlocked = self.unlocked_key.read().unwrap();
        if let Some(unlocked) = &*unlocked {
            state.update_master(&self.hardware, unlocked)?;
        } else {
            state.new_master(&self.hardware)?;
        }
        (self.update_state)(&*state);
        Ok(())
    }
}

impl<T: Keystore> Keystore for BackupKeystore<T> {
    fn as_lockable(&self) -> Option<&dyn LockableKeystore> {
        Some(self)
    }

    fn create_key(
        &self,
        alias: &str,
        r#type: KeyType,
        access_rules: crate::KeystoreAccessRules,
    ) -> Result<(), crate::KeystoreError> {
        let key = SoftwareKeystoreKey::new(r#type)?;

        let exported = key.export()?;
        self.import_new_key(alias, key, r#type, &exported, access_rules)
    }

    fn destroy_key(&self, alias: &str) -> Result<(), KeystoreError> {
        self.hardware.destroy_key(alias)?;
        let mut state = self.state.write().expect("Failed to write!");
        state.keys.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeystoreError> {
        self.hardware.list_keys()
    }

    fn set_secret(&self, alias: &str, secret: &[u8]) -> Result<(), KeystoreError> {
        self.hardware.ensure_exists(
            "keystore:secret",
            KeyType::Aes(256),
            KeystoreAccessRules {
                block_modes: vec![EncryptMode::Gcm],
                can_encrypt: true,
                can_decrypt: true,
                ..Default::default()
            },
        )?;
        let ciphertext = self
            .hardware
            .encrypt("keystore:secret", secret, &mut EncryptMode::Gcm)?;

        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.insert(alias.to_string(), ciphertext.into());
        (self.update_state)(&*state);
        Ok(())
    }

    fn get_secret(&self, alias: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
        let state = self.state.read().expect("Failed to write!");
        Ok(if let Some(secret) = state.secrets.get(alias) {
            Some(
                self.hardware
                    .decrypt("keystore:secret", secret.as_ref(), &EncryptMode::Gcm)?,
            )
        } else {
            None
        })
    }

    fn delete_secret(&self, alias: &str) -> Result<(), KeystoreError> {
        let mut state = self.state.write().expect("Failed to write!");
        state.secrets.remove(alias);
        (self.update_state)(&*state);
        Ok(())
    }

    fn import_key(
        &self,
        alias: &str,
        r#type: KeyType,
        priv_key: &[u8],
        access_rules: KeystoreAccessRules,
    ) -> Result<(), KeystoreError> {
        let key = SoftwareKeystoreKey::import(priv_key, r#type)?;
        self.import_new_key(alias, key, r#type, priv_key, access_rules)
    }

    fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError> {
        self.hardware.get_key_type(alias)
    }

    fn sign(
        &self,
        alias: &str,
        digest: crate::KeystoreDigest,
        padding: crate::KeystorePadding,
        data: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.sign(alias, digest, padding, data)
    }

    fn verify(
        &self,
        alias: &str,
        digest: crate::KeystoreDigest,
        padding: crate::KeystorePadding,
        data: &[u8],
        sig: &[u8],
    ) -> Result<bool, KeystoreError> {
        self.hardware.verify(alias, digest, padding, data, sig)
    }

    fn get_public_key(&self, alias: &str) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.get_public_key(alias)
    }

    fn derive(&self, alias: &str, peer: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.derive(alias, peer)
    }

    fn encrypt(
        &self,
        alias: &str,
        plaintext: &[u8],
        mode: &mut EncryptMode,
    ) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.encrypt(alias, plaintext, mode)
    }

    fn decrypt(
        &self,
        alias: &str,
        ciphertext: &[u8],
        mode: &EncryptMode,
    ) -> Result<Vec<u8>, KeystoreError> {
        self.hardware.decrypt(alias, ciphertext, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;

    #[derive(Default)]
    struct TestHardware {
        keys: RwLock<HashMap<String, Vec<u8>>>,
        imports: AtomicUsize,
        fail_import: bool,
        pause_first_import: Option<(mpsc::Sender<()>, Mutex<mpsc::Receiver<()>>)>,
    }

    impl Keystore for TestHardware {
        fn create_key(
            &self,
            _: &str,
            _: KeyType,
            _: KeystoreAccessRules,
        ) -> Result<(), KeystoreError> {
            panic!("backup store must import its prepared key")
        }
        fn destroy_key(&self, _: &str) -> Result<(), KeystoreError> {
            panic!("existing keys must not be deleted")
        }
        fn list_keys(&self) -> Result<Vec<String>, KeystoreError> {
            Ok(self.keys.read().unwrap().keys().cloned().collect())
        }
        fn import_key(
            &self,
            alias: &str,
            _: KeyType,
            key: &[u8],
            _: KeystoreAccessRules,
        ) -> Result<(), KeystoreError> {
            let previous = self.imports.fetch_add(1, Ordering::SeqCst);
            if previous == 0 {
                if let Some((entered, release)) = &self.pause_first_import {
                    entered.send(()).unwrap();
                    release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap();
                }
            }
            if self.fail_import {
                return Err(KeystoreError::KeystoreError(
                    "synthetic import failure".to_string(),
                ));
            }
            // Deliberately permits overwrite, so preservation depends on the wrapper guard.
            self.keys
                .write()
                .unwrap()
                .insert(alias.to_string(), key.to_vec());
            Ok(())
        }
        fn get_key_type(&self, alias: &str) -> Result<Option<KeyType>, KeystoreError> {
            Ok(self
                .keys
                .read()
                .unwrap()
                .get(alias)
                .map(|key| KeyType::Aes(key.len() as u16 * 8)))
        }
        fn set_secret(&self, _: &str, _: &[u8]) -> Result<(), KeystoreError> {
            panic!("test must not write secrets")
        }
        fn get_secret(&self, _: &str) -> Result<Option<Vec<u8>>, KeystoreError> {
            Err(KeystoreError::NotSupported)
        }
        fn delete_secret(&self, _: &str) -> Result<(), KeystoreError> {
            panic!("test must not delete secrets")
        }
        fn sign(
            &self,
            _: &str,
            _: KeystoreDigest,
            _: KeystorePadding,
            _: &[u8],
        ) -> Result<Vec<u8>, KeystoreError> {
            Err(KeystoreError::NotSupported)
        }
        fn verify(
            &self,
            _: &str,
            _: KeystoreDigest,
            _: KeystorePadding,
            _: &[u8],
            _: &[u8],
        ) -> Result<bool, KeystoreError> {
            Err(KeystoreError::NotSupported)
        }
        fn get_public_key(&self, _: &str) -> Result<Vec<u8>, KeystoreError> {
            Err(KeystoreError::NotSupported)
        }
        fn derive(&self, _: &str, _: &[u8]) -> Result<Vec<u8>, KeystoreError> {
            Err(KeystoreError::NotSupported)
        }
        fn encrypt(
            &self,
            alias: &str,
            data: &[u8],
            _: &mut EncryptMode,
        ) -> Result<Vec<u8>, KeystoreError> {
            let keys = self.keys.read().unwrap();
            contained_gcm_encrypt(keys.get(alias).ok_or(KeystoreError::KeyNotFound)?, data)
        }
        fn decrypt(
            &self,
            alias: &str,
            data: &[u8],
            _: &EncryptMode,
        ) -> Result<Vec<u8>, KeystoreError> {
            let keys = self.keys.read().unwrap();
            contained_gcm_decrypt(keys.get(alias).ok_or(KeystoreError::KeyNotFound)?, data)
        }
    }

    fn test_store(hardware: TestHardware) -> (BackupKeystore<TestHardware>, Arc<AtomicUsize>) {
        // Only ephemeral synthetic material; no platform keystore or filesystem access.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let master = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let updates = Arc::new(AtomicUsize::new(0));
        let update_count = updates.clone();
        let store = BackupKeystore {
            state: RwLock::new(BackupKeystoreState {
                keys: HashMap::new(),
                secrets: HashMap::new(),
                master_key: master.public_key_to_der().unwrap().into(),
                encrypted_master_key: vec![0; 16].into(),
            }),
            update_state: Box::new(move |_| {
                update_count.fetch_add(1, Ordering::SeqCst);
            }),
            hardware,
            unlocked_key: RwLock::new(Some(master)),
        };
        (store, updates)
    }

    fn snapshot(store: &BackupKeystore<TestHardware>) -> Vec<u8> {
        plist_to_bin(&*store.state.read().unwrap()).unwrap()
    }

    fn create_or_import(
        store: &BackupKeystore<TestHardware>,
        create: bool,
    ) -> Result<(), KeystoreError> {
        if create {
            store.create_key("test:identity", KeyType::Aes(256), Default::default())
        } else {
            store.import_key(
                "test:identity",
                KeyType::Aes(256),
                &[7; 32],
                Default::default(),
            )
        }
    }

    #[test]
    fn restored_backup_without_hardware_rejects_create_and_import() {
        let (store, updates) = test_store(TestHardware::default());
        {
            let mut state = store.state.write().unwrap();
            let encoded = plist_to_bin(&SoftwareKeystoreKey::Aes(vec![9; 32])).unwrap();
            let backup = BackedUpData::new(state.master_key.as_ref(), &encoded).unwrap();
            state.keys.insert("test:identity".to_string(), backup);
        }
        *store.unlocked_key.write().unwrap() = None;
        let before = snapshot(&store);
        for create in [true, false] {
            assert!(matches!(
                create_or_import(&store, create),
                Err(KeystoreError::KeyAlreadyExists)
            ));
        }
        assert!(matches!(
            store.ensure_exists("test:identity", KeyType::Aes(256), Default::default()),
            Err(KeystoreError::KeyAlreadyExists)
        ));
        assert_eq!(snapshot(&store), before);
        assert_eq!(updates.load(Ordering::SeqCst), 0);
        assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 0);
        assert!(store.hardware.keys.read().unwrap().is_empty());
    }

    #[test]
    fn existing_hardware_alias_is_not_overwritten_or_backed_up() {
        let (store, updates) = test_store(TestHardware::default());
        store
            .hardware
            .keys
            .write()
            .unwrap()
            .insert("test:identity".to_string(), vec![9; 32]);
        let before = snapshot(&store);
        for create in [true, false] {
            assert!(matches!(
                create_or_import(&store, create),
                Err(KeystoreError::KeyAlreadyExists)
            ));
        }
        assert_eq!(snapshot(&store), before);
        assert_eq!(updates.load(Ordering::SeqCst), 0);
        assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.hardware.keys.read().unwrap()["test:identity"],
            vec![9; 32]
        );
    }

    #[test]
    fn hardware_import_error_leaves_serialized_backup_unchanged() {
        let (store, updates) = test_store(TestHardware {
            fail_import: true,
            ..Default::default()
        });
        let before = snapshot(&store);
        for create in [true, false] {
            assert!(matches!(
                create_or_import(&store, create),
                Err(KeystoreError::KeystoreError(message)) if message == "synthetic import failure"
            ));
            assert_eq!(snapshot(&store), before);
            assert_eq!(updates.load(Ordering::SeqCst), 0);
            assert!(store.hardware.keys.read().unwrap().is_empty());
        }
        assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn backup_preparation_error_does_not_import_hardware() {
        let (store, updates) = test_store(TestHardware::default());
        store.state.write().unwrap().master_key = vec![0; 4].into();
        let before = snapshot(&store);
        for create in [true, false] {
            assert!(matches!(
                create_or_import(&store, create),
                Err(KeystoreError::SoftwareError(_))
            ));
        }
        assert_eq!(snapshot(&store), before);
        assert_eq!(updates.load(Ordering::SeqCst), 0);
        assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 0);
        assert!(store.hardware.keys.read().unwrap().is_empty());
    }

    #[test]
    fn valid_backup_create_and_import_preserve_key_material() {
        for create in [true, false] {
            let (store, updates) = test_store(TestHardware::default());
            create_or_import(&store, create).unwrap();
            let saved = store.get_priv_key("test:identity").unwrap().export().unwrap();
            assert_eq!(store.hardware.keys.read().unwrap()["test:identity"], saved);
            if !create {
                assert_eq!(saved, vec![7; 32]);
            }
            let before = snapshot(&store);
            store
                .ensure_exists("test:identity", KeyType::Aes(256), Default::default())
                .unwrap();
            for duplicate_create in [true, false] {
                assert!(matches!(
                    create_or_import(&store, duplicate_create),
                    Err(KeystoreError::KeyAlreadyExists)
                ));
            }
            assert_eq!(store.hardware.keys.read().unwrap()["test:identity"], saved);
            let ciphertext = store
                .encrypt("test:identity", b"synthetic", &mut EncryptMode::Gcm)
                .unwrap();
            assert_eq!(
                store.decrypt("test:identity", &ciphertext, &EncryptMode::Gcm).unwrap(),
                b"synthetic"
            );
            assert_eq!(snapshot(&store), before);
            assert_eq!(updates.load(Ordering::SeqCst), 1);
            assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn concurrent_create_and_import_of_same_alias_do_not_overwrite() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (store, updates) = test_store(TestHardware {
            pause_first_import: Some((entered_tx, Mutex::new(release_rx))),
            ..Default::default()
        });
        let (created, imported, held_lock) = std::thread::scope(|scope| {
            let create = scope.spawn(|| create_or_import(&store, true));
            entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            // Observe the critical section while hardware is paused, without timing sleeps.
            let held_lock = matches!(
                store.state.try_write(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            let import = scope.spawn(|| create_or_import(&store, false));
            release_tx.send(()).unwrap();
            (create.join().unwrap(), import.join().unwrap(), held_lock)
        });
        assert!(held_lock);
        created.unwrap();
        assert!(matches!(imported, Err(KeystoreError::KeyAlreadyExists)));
        assert_eq!(store.hardware.imports.load(Ordering::SeqCst), 1);
        assert_eq!(updates.load(Ordering::SeqCst), 1);
        assert_eq!(store.state.read().unwrap().keys.len(), 1);
        assert_eq!(
            store.hardware.keys.read().unwrap()["test:identity"],
            store.get_priv_key("test:identity").unwrap().export().unwrap()
        );
    }
}
