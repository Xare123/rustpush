//! Ticket-authenticated native push signing. The private key never leaves iOS.
use crate::{util::REQWEST_NO_REDIRECT, PushError};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Signer,
    x509::X509,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PREFIX: &str = "ob-push-v1.";
const REQUEST_DOMAIN: &[u8] = b"OBPushRequest1\0";
const RESPONSE_DOMAIN: &[u8] = b"OBPushResponse1\0";
fn invalid() -> PushError {
    PushError::APSNotReady(
        "native push identity or signing response unavailable; saved credentials kept",
    )
}

/// Public certificate and physical owner only. No ticket or key is stored here.
#[derive(Clone, Serialize, Deserialize)]
pub struct NativePushIdentity {
    #[serde(
        serialize_with = "crate::util::bin_serialize",
        deserialize_with = "crate::util::bin_deserialize"
    )]
    pub certificate: Vec<u8>,
    pub device_id: String,
    pub device_uuid: String,
}

#[derive(Clone)]
pub struct NativePushTransport {
    pub host: String,
    pub code: String,
    pub beeper_token: Option<String>,
    pub device_id: String,
    pub device_uuid: String,
}

pub fn certificate_public_key(der: &[u8]) -> Result<PKey<Public>, PushError> {
    if !(129..=8192).contains(&der.len()) {
        return Err(invalid());
    }
    let cert = X509::from_der(der).map_err(|_| invalid())?;
    if cert.to_der().map_err(|_| invalid())? != der {
        return Err(invalid());
    }
    let key = cert.public_key().map_err(|_| invalid())?;
    if key.id() != Id::RSA || ![1024, 2048, 3072, 4096].contains(&key.bits()) {
        return Err(invalid());
    }
    Ok(key)
}

impl NativePushIdentity {
    pub fn matches(&self, transport: &NativePushTransport) -> bool {
        !self.device_id.is_empty()
            && !self.device_uuid.is_empty()
            && self.device_id.eq_ignore_ascii_case(&transport.device_id)
            && self.device_uuid == transport.device_uuid
            && certificate_public_key(&self.certificate).is_ok()
    }
    pub fn same_owner(&self, other: &Self) -> bool {
        self.device_id.eq_ignore_ascii_case(&other.device_id)
            && self.device_uuid == other.device_uuid
            && self.certificate == other.certificate
    }
}

fn now_ms() -> Result<u64, PushError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .filter(|v| *v > 0 && *v <= i64::MAX as u64)
        .ok_or_else(invalid)
}
fn mac(domain: &[u8], data: &[u8], code: &str) -> Result<Vec<u8>, PushError> {
    if !valid_code(code) {
        return Err(invalid());
    }
    let key = PKey::hmac(code.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(domain)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}
fn valid_code(code: &str) -> bool {
    code.len() == 19
        && code.bytes().enumerate().all(|(i, b)| {
            if [4, 9, 14].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_uppercase() || b.is_ascii_digit()
            }
        })
}

struct NativeRequest {
    command: String,
    hash: [u8; 32],
    issued: u64,
    operation: u8,
    certificate: Vec<u8>,
    signed_digest: Option<[u8; 20]>,
}

impl NativeRequest {
    fn new(
        operation: u8,
        cert: &[u8],
        nonce: &[u8],
        bag: u8,
        digest: Option<[u8; 20]>,
        code: &str,
        issued: u64,
        id: [u8; 16],
    ) -> Result<Self, PushError> {
        if issued == 0 || issued > i64::MAX as u64 || id == [0; 16] {
            return Err(invalid());
        }
        let mut payload = vec![1, operation];
        payload.extend_from_slice(&issued.to_be_bytes());
        payload.extend_from_slice(&id);
        payload.extend_from_slice(&if operation == 0 {
            [0; 32]
        } else {
            openssl::sha::sha256(cert)
        });
        match operation {
            0 if cert.is_empty() && nonce.is_empty() && bag == 0 && digest.is_none() => {}
            1 | 2
                if certificate_public_key(cert).is_ok()
                    && nonce.len() == 17
                    && nonce[0] == operation - 1 =>
            {
                let stamp = u64::from_be_bytes(nonce[1..9].try_into().map_err(|_| invalid())?);
                if stamp == 0 || stamp > i64::MAX as u64 || stamp.abs_diff(issued) > 30_000 {
                    return Err(invalid());
                }
                payload.extend_from_slice(nonce);
                if operation == 2 {
                    if !(1..=4).contains(&bag) || digest.is_none() {
                        return Err(invalid());
                    }
                    payload.push(bag);
                    payload.extend_from_slice(&digest.ok_or_else(invalid)?);
                } else if bag != 0 || digest.is_some() {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        let request_mac = mac(REQUEST_DOMAIN, &payload, code)?;
        payload.extend_from_slice(&request_mac);
        let hash = openssl::sha::sha256(&payload);
        let command = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(payload));
        if command.len() > 256 {
            return Err(invalid());
        }
        Ok(Self {
            command,
            hash,
            issued,
            operation,
            certificate: cert.to_vec(),
            signed_digest: if operation == 1 {
                Some(openssl::sha::sha1(nonce))
            } else {
                digest
            },
        })
    }
    fn response(&self, raw: &[u8], code: &str, now: u64) -> Result<Vec<u8>, PushError> {
        if now < self.issued || now - self.issued > 30_000 || raw.len() > 24_576 {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            ob_push_v1: Response,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Response {
            schema: u8,
            request_sha256: String,
            certificate: String,
            signature: String,
            mac: String,
        }
        let value: Envelope = serde_json::from_slice(raw).map_err(|_| invalid())?;
        let value = value.ob_push_v1;
        fn decode(text: &str, max: usize) -> Result<Vec<u8>, PushError> {
            if text.len() > max * 2 {
                return Err(invalid());
            }
            let bytes = STANDARD.decode(text).map_err(|_| invalid())?;
            if bytes.len() > max || STANDARD.encode(&bytes) != text {
                return Err(invalid());
            }
            Ok(bytes)
        }
        if value.schema != 1 || decode(&value.request_sha256, 32)? != self.hash {
            return Err(invalid());
        }
        let cert = decode(&value.certificate, 8192)?;
        let sig = decode(&value.signature, 512)?;
        let key = certificate_public_key(&cert)?;
        if self.operation == 0 {
            if !sig.is_empty() {
                return Err(invalid());
            }
        } else if cert != self.certificate || sig.len() != key.bits() as usize / 8 {
            return Err(invalid());
        }
        let mut bound = self.hash.to_vec();
        bound.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        bound.extend_from_slice(&cert);
        bound.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        bound.extend_from_slice(&sig);
        let actual_mac = decode(&value.mac, 32)?;
        let expected_mac = mac(RESPONSE_DOMAIN, &bound, code)?;
        if actual_mac.len() != 32 || !memcmp::eq(&actual_mac, &expected_mac) {
            return Err(invalid());
        }
        if let Some(digest) = self.signed_digest {
            // Native HTTP signs the already SHA1-hashed production payload.
            // Verify the exact SHA1 DigestInfo, not a hash of that digest.
            let mut info = vec![
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ];
            info.extend_from_slice(&digest);
            let rsa = key.rsa()?;
            let mut recovered = vec![0u8; rsa.size() as usize];
            let count = rsa
                .public_decrypt(&sig, &mut recovered, Padding::PKCS1)
                .map_err(|_| invalid())?;
            if count != info.len() || !memcmp::eq(&recovered[..count], &info) {
                return Err(invalid());
            }
            Ok([&[1, 1][..], &sig].concat())
        } else {
            Ok(cert)
        }
    }
}

impl NativePushTransport {
    async fn request(
        &self,
        operation: u8,
        cert: &[u8],
        nonce: &[u8],
        bag: u8,
        digest: Option<[u8; 20]>,
    ) -> Result<Vec<u8>, PushError> {
        let url = reqwest::Url::parse(&self.host).map_err(|_| invalid())?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || self.device_id.is_empty()
            || self.device_uuid.is_empty()
        {
            return Err(invalid());
        }
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        let request = NativeRequest::new(
            operation,
            cert,
            nonce,
            bag,
            digest,
            &self.code,
            now_ms()?,
            id,
        )?;
        let endpoint = format!(
            "{}/api/v1/bridge/{}",
            self.host.trim_end_matches('/'),
            request.command
        );
        let mut builder = REQWEST_NO_REDIRECT
            .post(endpoint)
            .bearer_auth(&self.code)
            .header("Content-Length", "0")
            .timeout(Duration::from_secs(8));
        if let Some(token) = &self.beeper_token {
            builder = builder.header("X-Beeper-Access-Token", token);
        }
        // Drop reqwest errors here: they contain the private command URL.
        let mut response = builder.send().await.map_err(|_| invalid())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(invalid());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
            if body.len() + chunk.len() > 24_576 {
                return Err(invalid());
            }
            body.extend_from_slice(&chunk);
        }
        request.response(&body, &self.code, now_ms()?)
    }
    pub async fn discover(&self) -> Result<NativePushIdentity, PushError> {
        Ok(NativePushIdentity {
            certificate: self.request(0, &[], &[], 0, None).await?,
            device_id: self.device_id.clone(),
            device_uuid: self.device_uuid.clone(),
        })
    }
    pub async fn sign_connect(
        &self,
        identity: &NativePushIdentity,
        nonce: &[u8],
    ) -> Result<Vec<u8>, PushError> {
        if !identity.matches(self) {
            return Err(invalid());
        }
        self.request(1, &identity.certificate, nonce, 0, None).await
    }
    pub async fn sign_http(
        &self,
        identity: &NativePushIdentity,
        nonce: &[u8],
        bag: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, PushError> {
        if !identity.matches(self) {
            return Err(invalid());
        }
        let bag = match bag {
            "id-get-handles" => 1,
            "id-get-dependent-registrations" => 2,
            "id-provision-alias" => 3,
            "id-register" => 4,
            _ => return Err(invalid()),
        };
        self.request(
            2,
            &identity.certificate,
            nonce,
            bag,
            Some(openssl::sha::sha1(payload)),
        )
        .await
    }
}

#[cfg(test)]
mod tests;

/// Feature-only driver of the NORMAL resource and HTTP signing paths. It never
/// sends the signed HTTP request, opens an Apple account, or writes a profile.
#[cfg(feature = "native-aps-qualification")]
pub async fn qualify_native_client(mut config: crate::RelayConfig) -> serde_json::Value {
    use crate::{auth::SignedRequest, APSConnectionResource, APSState};
    use std::sync::Arc;
    let mut report = serde_json::json!({"schema":1,"status":"native-push-client-unqualified",
        "normal_aps_connected":false,"native_owner_verified":false,"token_bytes":0,
        "http_signature_verified":false,"close_requested":false,"activation_requests":0,
        "account_requests":0,"message_requests":0,"cloudkit_requests":0,"profile_writes":0});
    if config.host != "https://registration-relay.beeper.com" || !valid_code(&config.code) {
        return report;
    }
    let versions = crate::RelayConfig::get_versions_with_capabilities(
        &config.host,
        &config.code,
        &config.beeper_token,
    )
    .await;
    let Ok((version, true, true)) = versions else {
        report["status"] = "native-capability-unavailable".into();
        return report;
    };
    let original = config.clone();
    config.version = version;
    config.native_auth_v1 = true;
    config.native_push_v1 = true;
    let Some(config) = original.native_replacement(&config) else {
        report["status"] = "native-owner-mismatch".into();
        return report;
    };
    let (connection, error) =
        APSConnectionResource::new(Arc::new(config), Some(APSState::default())).await;
    if error.is_some() {
        connection.close();
        report["close_requested"] = true.into();
        return report;
    }
    let snapshot = connection.state.read().await.clone();
    if snapshot.token.is_none()
        || snapshot.keypair.is_some()
        || !snapshot.has_push_identity()
        || snapshot.native_push.is_none()
    {
        connection.close();
        report["close_requested"] = true.into();
        return report;
    }
    report["normal_aps_connected"] = true.into();
    report["native_owner_verified"] = true.into();
    report["token_bytes"] = 32.into();
    let signed = SignedRequest::new("id-get-handles", reqwest::Method::GET)
        .sign_push(&snapshot)
        .await;
    if signed.is_ok() {
        report["http_signature_verified"] = true.into();
        report["status"] = "native-push-client-accepted".into();
    }
    drop(signed);
    connection.close();
    report["close_requested"] = true.into();
    report
}
