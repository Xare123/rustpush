use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use crate::{
    activation::ActivationInfo,
    util::REQWEST,
    DebugMeta, OSConfig, PushError, RegisterMeta,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use plist::{Dictionary, Value};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct DataResp {
    data: String,
}

#[derive(Deserialize)]
pub struct VersionsResp {
    versions: Versions,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Versions {
    software_build_id: String,
    software_name: String,
    software_version: String,
    serial_number: String,
    hardware_version: String,
    unique_device_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    pub version: Versions,
    pub icloud_ua: String,
    pub aoskit_version: String,
    pub dev_uuid: String,
    pub protocol_version: u32,
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
    pub udid: Option<String>,
    /// Persist the capability only, never the transient headers or signature.
    #[serde(default)]
    pub native_auth_v1: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub native_push_v1: bool,
}

impl RelayConfig {
    pub async fn get_versions(
        host: &str,
        code: &str,
        beeper_token: &Option<String>,
    ) -> Result<Versions, PushError> {
        Ok(Self::get_versions_with_native_auth(host, code, beeper_token).await?.0)
    }

    pub async fn get_versions_with_native_auth(
        host: &str,
        code: &str,
        beeper_token: &Option<String>,
    ) -> Result<(Versions, bool), PushError> {
        let (versions, native_auth, _) = Self::get_versions_with_capabilities(host, code, beeper_token).await?;
        Ok((versions, native_auth))
    }

    pub async fn get_versions_with_capabilities(
        host: &str, code: &str, beeper_token: &Option<String>,
    ) -> Result<(Versions, bool, bool), PushError> {
        let mut data = REQWEST
            .post(format!("{}/api/v1/bridge/get-version-info", host))
            .bearer_auth(code)
            .header("Content-Length", "0");

        if let Some(token) = beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {}
            404 => return Err(PushError::DeviceNotFound),
            _status => return Err(PushError::RelayError(_status, result.text().await?)),
        }

        // Extract only capability presence before deserializing the original
        // six-field persistent type. Unknown proof fields are intentionally lost.
        let value: serde_json::Value = result.json().await?;
        let native_auth = has_native_auth_capability(&value);
        let native_push = native_auth && value.pointer("/versions/ob_push_capabilities")
            .and_then(serde_json::Value::as_str) == Some("native-push-v1");
        let result: VersionsResp = serde_json::from_value(value)?;
        Ok((result.versions, native_auth, native_push))
    }

    pub fn native_auth_config(&self) -> Option<omnisette::native_relay::NativeRelayConfig> {
        self.native_auth_v1.then(|| omnisette::native_relay::NativeRelayConfig {
            host: self.host.clone(), code: self.code.clone(), beeper_token: self.beeper_token.clone(),
            identity: omnisette::native_relay::NativeRelayIdentity {
                device_id: self.version.unique_device_id.clone(),
                serial_number: self.version.serial_number.clone(),
                hardware_version: self.version.hardware_version.clone(),
            },
        })
    }

    /// Replace only the relay transport for the same physical iPhone. Keep the
    /// locally generated device UUID/UDID and protocol context. A new ticket
    /// must not silently become a new activation identity.
    pub fn native_replacement(&self, replacement: &Self) -> Option<Self> {
        let old = &self.version;
        let new = &replacement.version;
        if !replacement.native_auth_v1
            || old.unique_device_id.is_empty()
            || old.serial_number.is_empty()
            || old.hardware_version.is_empty()
            || !old.unique_device_id.eq_ignore_ascii_case(&new.unique_device_id)
            || old.serial_number != new.serial_number
            || old.hardware_version != new.hardware_version
        {
            return None;
        }
        let mut retained = self.clone();
        retained.version = replacement.version.clone();
        retained.host = replacement.host.clone();
        retained.code = replacement.code.clone();
        retained.beeper_token = replacement.beeper_token.clone();
        retained.native_auth_v1 = true;
        retained.native_push_v1 = replacement.native_push_v1;
        Some(retained)
    }
}

fn has_native_auth_capability(value: &serde_json::Value) -> bool {
    value.pointer("/versions/ob_auth_capabilities").and_then(serde_json::Value::as_str) == Some("native-account-v1")
        || value.pointer("/versions/ob_auth_bundle_v1").is_some()
}

fn decode_relay_validation(data: &str) -> Result<Vec<u8>, PushError> {
    let invalid = || omnisette::AnisetteError::InvalidArgument("unusable relay device-validation data; saved device details were not reset".into());
    if data.is_empty() || data.len() > 65_536 { return Err(invalid().into()); }
    let bytes = STANDARD.decode(data).map_err(|_| invalid())?;
    if bytes.is_empty() { return Err(invalid().into()); }
    Ok(bytes)
}

#[cfg(test)]
mod native_auth_persistence_tests {
    use super::*;
    use serde_json::json;

    fn versions() -> serde_json::Value {
        json!({"software_build_id":"synthetic-build","software_name":"iPhone OS",
            "software_version":"synthetic-version","serial_number":"synthetic-serial",
            "hardware_version":"synthetic-model","unique_device_id":"synthetic-device"})
    }

    #[test]
    fn legacy_versions_discard_native_auth_extension_before_persistence() {
        let mut wire=versions();
        wire["ob_auth_bundle_v1"]=json!("synthetic-proof-must-not-persist");
        wire["ob_auth_capabilities"]=json!("native-account-v1");
        let response:VersionsResp=serde_json::from_value(json!({"versions":wire})).unwrap();
        let saved=serde_json::to_value(response.versions).unwrap();
        assert_eq!(saved,versions());
        assert!(!saved.to_string().contains("synthetic-proof-must-not-persist"));
    }

    #[test]
    fn native_capability_survives_temporary_proof_unavailability_without_legacy_fallback() {
        let mut wire=json!({"versions":versions()});
        assert!(!has_native_auth_capability(&wire));
        wire["versions"]["ob_auth_capabilities"]=json!("native-account-v1");
        assert!(has_native_auth_capability(&wire));
        // No bundle was returned, but a native-capable helper must still select
        // native mode so its failure occurs before SRP, not on another provider.
        assert!(wire["versions"].get("ob_auth_bundle_v1").is_none());
        wire["versions"].as_object_mut().unwrap().remove("ob_auth_capabilities");
        wire["versions"]["ob_auth_bundle_v1"]=json!("");
        assert!(has_native_auth_capability(&wire));
    }

    #[test]
    fn device_validation_bytes_are_unchanged_and_bad_base64_returns_an_error_not_a_panic() {
        let bytes=vec![1,2,3,4,5];
        assert_eq!(decode_relay_validation(&STANDARD.encode(&bytes)).unwrap(),bytes);
        for value in [String::new(),"not-base64".into(),"A".repeat(65_537)] {
            assert!(decode_relay_validation(&value).is_err());
        }
    }

    #[test]
    fn old_relay_config_defaults_to_legacy_and_new_config_persists_only_capability() {
        let mut value=json!({"version":versions(),"icloud_ua":"synthetic-agent","aoskit_version":"synthetic-kit",
            "dev_uuid":"synthetic-uuid","protocol_version":1660,"host":"https://relay.example",
            "code":"synthetic-code","beeper_token":null,"udid":"synthetic-udid"});
        let old:RelayConfig=serde_json::from_value(value.clone()).unwrap();
        assert!(!old.native_auth_v1);
        assert!(old.native_auth_config().is_none());
        value["native_auth_v1"]=json!(true);
        let new:RelayConfig=serde_json::from_value(value).unwrap();
        assert!(new.native_auth_config().is_some());
        let saved=serde_json::to_value(new).unwrap();
        assert_eq!(saved["native_auth_v1"],json!(true));
        assert!(saved["version"].get("ob_auth_bundle_v1").is_none());
    }
}

#[async_trait]
impl OSConfig for RelayConfig {
    fn native_push_transport(&self) -> Option<crate::native_push::NativePushTransport> {
        self.native_push_v1.then(|| crate::native_push::NativePushTransport {
            host:self.host.clone(),code:self.code.clone(),beeper_token:self.beeper_token.clone(),
            device_id:self.version.unique_device_id.clone(),device_uuid:self.dev_uuid.clone(),
        })
    }
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.version.software_build_id.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: "iMac13,1".to_string(),
            product_version: self.version.software_version.clone(),
            serial_number: self.version.serial_number.clone(),
            unique_device_id: self.version.unique_device_id.clone().to_uppercase(),
        }
    }

    fn get_udid(&self) -> String {
        self.udid.clone().expect("missing udid!")
    }

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_serial_number(&self) -> String {
        self.version.serial_number.clone()
    }

    fn get_mme_clientinfo(&self, item: &str) -> String {
        format!(
            "<{}> <{};{};{}> <{}>",
            self.version.hardware_version,
            self.version.software_name,
            self.version.software_version,
            self.version.software_build_id,
            item
        )
    }

    fn get_adi_mme_info(&self, item: &str, require_mac: bool) -> String {
        if require_mac {
            // must be mac for ClearADI
            format!("<iMac13,1> <macOS;13.6.4;22G513> <{}>", item)
        } else {
            self.get_mme_clientinfo(item)
        }
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [("X-Apple-I-SRL-NO", &self.version.serial_number)]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn get_version_ua(&self) -> String {
        format!(
            "[{},{},{},{}]",
            self.version.software_name,
            self.version.software_version,
            self.version.software_build_id,
            self.version.hardware_version
        )
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/signin/v2/login"
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.dev_uuid.clone()
    }

    fn get_device_name(&self) -> String {
        format!("iPhone-{}", self.version.serial_number)
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        let mut data = REQWEST
            .post(format!("{}/api/v1/bridge/get-validation-data", self.host))
            .bearer_auth(&self.code)
            .header("Content-Length", "0");

        if let Some(token) = &self.beeper_token {
            data = data.header("X-Beeper-Access-Token", token.clone());
        }

        let result = data.send().await?;

        match result.status().as_u16() {
            200 => {}
            404 => return Err(PushError::DeviceNotFound),
            _status => return Err(PushError::RelayError(_status, result.text().await?)),
        }

        let result: DataResp = result.json().await?;

        decode_relay_validation(&result.data)
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.version.hardware_version.clone(),
            os_version: format!(
                "{},{},{}",
                self.version.software_name,
                self.version.software_version,
                self.version.software_build_id
            ),
            software_version: self.version.software_build_id.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.version.software_version.clone(),
            hardware_version: self.version.hardware_version.clone(),
            serial_number: self.version.serial_number.clone(),
        }
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            // apple pay
            ("ap", Value::String("0".to_string())),
            (
                "d",
                Value::String(format!(
                    "{:.6}",
                    apple_epoch.elapsed().unwrap().as_secs_f64()
                )),
            ),
            // device type
            ("dt", Value::Integer(1.into())),
            // green tea - ??
            ("gt", Value::String("0".to_string())),
            // supports handoff
            ("h", Value::String("1".to_string())),
            // supports phone calls
            ("p", Value::String("0".to_string())),
            ("pb", Value::String(self.version.software_build_id.clone())),
            (
                "pn",
                Value::String(if self.version.software_name == "MacOS" {
                    "macOS".to_string()
                } else {
                    self.version.software_name.clone()
                }),
            ),
            ("pv", Value::String(self.version.software_version.clone())),
            // mms router support
            ("m", Value::String("1".to_string())),
            // sms router support
            ("s", Value::String("1".to_string())),
            // tethering support
            // ec = enclosure color
            // c = data color
            // ss = service signatures
            // ktf = key transparency flags
            // ktv = key transparency version
            ("t", Value::String("0".to_string())),
            ("u", Value::String(self.dev_uuid.clone().to_uppercase())),
            // version
            ("v", Value::String("1".to_string())),
        ])
    }
}
