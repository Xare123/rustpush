use keystore::{
    keystore, KeystoreAccessRules, KeystoreDigest, KeystoreKey, KeystorePadding,
    KeystorePublicKey, KeystoreSignKey, RsaKey,
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Params},
    rsa::{Padding, Rsa},
    sign::Signer,
    x509::{X509Name, X509Req, X509},
};
use plist::{Data, Value};
use rand::{seq::SliceRandom, thread_rng};
use rasn::types::Oid;
use regex::Regex;
use reqwest::Version;
use serde::Serialize;
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{
        asn1::{BitString, Null, SetOfVec, Utf8StringRef},
        pem::LineEnding,
        Decode, Encode, EncodePem,
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    request::{CertReq, CertReqInfo},
    spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo},
};

use crate::{
    util::{get_nested_value, plist_to_buf, plist_to_string, KeyPair, KeyPairNew, REQWEST},
    OSConfig, PushError,
};

#[path = "activation_key_lifecycle.rs"]
mod activation_key_lifecycle;
use activation_key_lifecycle::{validate_certificate_public_key, CandidateKey};

// Never log Albert response bodies, certificates, request fields, or arbitrary
// headers. Both Apple rejection pages and malformed success responses used to
// collapse to the same certificate error, hiding the first failing boundary.
fn activation_diagnostic(
    status: reqwest::StatusCode,
    expected_origin: bool,
    content_type: Option<&str>,
    body: &str,
    reason: &'static str,
) -> String {
    let media = match content_type.map(|value| value.split(';').next().unwrap_or("").trim()) {
        Some("text/html") => "html",
        Some("application/x-buddyml") => "buddyml",
        Some("text/xml" | "application/xml" | "application/x-apple-plist") => "plist-or-xml",
        None => "missing",
        _ => "other",
    };
    format!(
        "activation_response status={} expected_origin={} media={} bytes={} reason={}",
        status.as_u16(), expected_origin, media, body.len(), reason,
    )
}

fn parse_activation_response(
    status: reqwest::StatusCode,
    expected_origin: bool,
    content_type: Option<&str>,
    body: &str,
) -> Result<Vec<u8>, PushError> {
    let report = |reason| {
        log::warn!(target: "rustpush::activation::diagnostic", "{}",
            activation_diagnostic(status, expected_origin, content_type, body, reason));
    };
    if !status.is_success() {
        report("http-status");
        return Err(PushError::StatusError(status));
    }
    if !expected_origin {
        report("unexpected-origin");
        return Err(PushError::AlbertCertParseError);
    }
    if body.contains("DEVICE_INFO_INTEGRITY_FAILED") {
        report("device-info-integrity-failed");
        return Err(PushError::AppleAuthResponse {
            stage: "push-activation", status: status.as_u16(),
            reason: "device-info-integrity-failed", bytes: body.len(),
        });
    }
    // Albert can return a pretty-printed plist inside Protocol. A line-oriented
    // dot rejected the entire HTTP 200 response before reading its certificate.
    let protocol = Regex::new(r"(?s)<Protocol>(.*)</Protocol>").unwrap();
    let captures = protocol.captures(body).ok_or_else(|| {
        report(if body.is_empty() {
            "empty-body"
        } else {
            "protocol-wrapper-missing"
        });
        PushError::AlbertCertParseError
    })?;
    let parsed: Value = plist::from_bytes(captures[1].as_bytes()).map_err(|error| {
        report("protocol-plist-invalid");
        PushError::from(error)
    })?;
    let certificate = get_nested_value(
        &parsed,
        &["device-activation", "activation-record", "DeviceCertificate"],
    )
    .and_then(|value| value.as_data())
    .ok_or_else(|| {
        report("device-certificate-missing");
        log::warn!(target: "rustpush::activation::diagnostic", "{}", activation_response_shape(&parsed));
        PushError::AlbertCertParseError
    })?;
    let certificate = X509::from_pem(certificate).and_then(|value| value.to_der())
        .map_err(|error| {
            report("device-certificate-invalid");
            PushError::from(error)
        })?;
    log::info!(target: "rustpush::activation::diagnostic", "{}",
        activation_diagnostic(status, expected_origin, content_type, body, "certificate-parsed"));
    Ok(certificate)
}

fn certificate_matches_key(certificate: &[u8], key: &RsaKey) -> Result<(), PushError> {
    let expected_public_key = key.get_public_key()?;
    validate_certificate_public_key(certificate, &expected_public_key)
}

fn activation_response_shape(parsed: &Value) -> String {
    fn kind(value: Option<&Value>) -> &'static str {
        match value {
            None => "missing",
            Some(Value::Dictionary(_)) => "dictionary",
            Some(Value::Array(_)) => "array",
            Some(Value::Data(_)) => "data",
            Some(Value::String(_)) => "string",
            Some(Value::Integer(_)) => "integer",
            Some(Value::Boolean(_)) => "boolean",
            _ => "other",
        }
    }
    // Fixed key names and value TYPES only, including alternative activation
    // wrappers. Do not print arbitrary dictionaries or strings from the server.
    let device = get_nested_value(parsed, &["device-activation"]);
    let record = get_nested_value(parsed, &["device-activation", "activation-record"]);
    let certificate = get_nested_value(parsed, &["device-activation", "activation-record", "DeviceCertificate"]);
    format!("activation_structure root={} device={} record={} certificate={} iphone={} macos={} direct_record={} error={} error_code={}",
        kind(Some(parsed)), kind(device), kind(record), kind(certificate),
        kind(get_nested_value(parsed, &["iphone-activation"])),
        kind(get_nested_value(parsed, &["macos-activation"])),
        kind(get_nested_value(parsed, &["activation-record"])),
        kind(get_nested_value(parsed, &["Error"])),
        kind(get_nested_value(parsed, &["ErrorCode"])),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActivationInfo {
    pub activation_randomness: String,
    pub activation_state: &'static str,
    pub build_version: String,
    pub device_cert_request: Data,
    pub device_class: String,
    pub product_type: String,
    pub product_version: String,
    pub serial_number: String,
    #[serde(rename = "UniqueDeviceID")]
    pub unique_device_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ActivationRequest {
    activation_info_complete: bool,
    #[serde(rename = "ActivationInfoXML")]
    activation_info_xml: Data,
    fair_play_cert_chain: Data,
    fair_play_signature: Data,
}

macro_rules! include_cert {
    ($name:literal) => {
        (
            include_bytes!(concat!("../certs/fairplay/", $name, ".crt")),
            include_bytes!(concat!("../certs/fairplay/", $name, ".pem")),
        )
    };
}

const FAIRPLAY_KEYS: &[(&'static [u8], &'static [u8])] = &[
    include_cert!("4056631661436364584235346952193"),
    include_cert!("4056631661436364584235346952194"),
    include_cert!("4056631661436364584235346952195"),
    include_cert!("4056631661436364584235346952196"),
    include_cert!("4056631661436364584235346952197"),
    include_cert!("4056631661436364584235346952198"),
    include_cert!("4056631661436364584235346952199"),
    include_cert!("4056631661436364584235346952200"),
    include_cert!("4056631661436364584235346952201"),
    include_cert!("4056631661436364584235346952208"),
];

fn fairplay_sign(data: &[u8]) -> Result<(&'static [u8], Vec<u8>), PushError> {
    let identity = *FAIRPLAY_KEYS.choose(&mut thread_rng()).expect("no keys!");
    let (cert, key) = identity;

    let key = PKey::private_key_from_der(&key)?;

    let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    Ok((cert, signer.sign_oneshot_to_vec(data)?))
}

pub async fn activate(os_config: &dyn OSConfig) -> Result<KeyPairNew<RsaKey>, PushError> {
    let key = RsaKey::create_new(
        &format!("activation:{}", os_config.get_serial_number()),
        1024,
        KeystoreAccessRules {
            signature_padding: vec![KeystorePadding::PKCS1],
            digests: vec![KeystoreDigest::Sha1],
            can_sign: true,
            ..Default::default()
        },
    )?;
    let key_alias = key.alias().to_owned();
    let key = CandidateKey::new(key, key_alias, |alias| {
        // The lifecycle owns only the freshly-created alias. Never remove the
        // legacy or previously committed activation key during rollback.
        let _ = keystore().destroy_key(alias);
    });

    let public_key = SubjectPublicKeyInfo::from_der(&key.key().get_public_key()?).unwrap();
    let request = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: RdnSequence(vec![RelativeDistinguishedName(
            SetOfVec::from_iter([AttributeTypeAndValue {
                oid: ObjectIdentifier::new("2.5.4.3").unwrap(),
                value: Utf8StringRef::new("Client Push Certificate")
                    .unwrap()
                    .into(),
            }])
            .unwrap(),
        )]),
        public_key,
        attributes: SetOfVec::new(),
    };

    let req_info = request.to_der().unwrap();

    let sign = key.key().sign(KeystoreDigest::Sha1, KeystorePadding::PKCS1, &req_info)?;

    let result = CertReq {
        info: request,
        algorithm: AlgorithmIdentifier {
            oid: ObjectIdentifier::new("1.2.840.113549.1.1.5").unwrap(),
            parameters: Some(Null.into()),
        },
        signature: BitString::from_bytes(&sign).unwrap(),
    };

    let csr = result.to_pem(LineEnding::LF).unwrap();

    let activation = os_config.build_activation_info(csr.into_bytes());
    let activation_url = format!(
        "https://albert.apple.com/deviceservices/deviceActivation?device={}",
        os_config.get_activation_device(),
    );
    let activation_bytes = plist_to_buf(&activation)?;

    let (fair_play_cert_chain, fair_play_signature) = fairplay_sign(&activation_bytes)?;

    let request = ActivationRequest {
        activation_info_complete: true,
        activation_info_xml: activation_bytes.into(),
        fair_play_cert_chain: fair_play_cert_chain.to_vec().into(),
        fair_play_signature: fair_play_signature.into(),
    };

    #[derive(Serialize)]
    #[serde(rename_all = "kebab-case")]
    struct FormBody {
        activation_info: String,
    }

    let activation_user_agent = os_config.get_normal_ua("ApplePushService/4.0");
    let response = REQWEST
        .post(activation_url)
        .header("User-Agent", activation_user_agent)
        .form(&FormBody {
            activation_info: plist_to_string(&request)?,
        })
        .send()
        .await?;
    let status = response.status();
    let expected_origin = response.url().origin().ascii_serialization() == "https://albert.apple.com";
    let content_type = response.headers().get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok()).map(str::to_owned);
    let body = response.text().await?;
    let certificate = parse_activation_response(status, expected_origin, content_type.as_deref(), &body)?;
    certificate_matches_key(&certificate, key.key())?;

    let key = key.commit();
    Ok(KeyPairNew {
        cert: certificate,
        private: key,
    })
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use reqwest::StatusCode;

    fn certificate_response() -> (String, Vec<u8>) {
        // Synthetic certificate, not an Apple credential or a trust fixture.
        let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let mut name = X509Name::builder().unwrap();
        name.append_entry_by_text("CN", "activation-parser-test").unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
        certificate.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap()).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();
        let parsed = Value::Dictionary(plist::Dictionary::from_iter([(
            "device-activation".to_owned(), Value::Dictionary(plist::Dictionary::from_iter([(
                "activation-record".to_owned(), Value::Dictionary(plist::Dictionary::from_iter([(
                    "DeviceCertificate".to_owned(), Value::Data(certificate.to_pem().unwrap()),
                )])),
            )])),
        )]));
        let xml = plist_to_string(&parsed).unwrap().lines().collect::<String>();
        (format!("<html><Protocol>{xml}</Protocol></html>"), certificate.to_der().unwrap())
    }

    #[test]
    fn accepts_existing_protocol_certificate_shape() {
        let (body, expected) = certificate_response();
        assert_eq!(parse_activation_response(StatusCode::OK, true, Some("text/html"), &body).unwrap(), expected);
    }

    #[test]
    fn accepts_multiline_protocol_certificate_without_changing_payload() {
        let (body, expected) = certificate_response();
        for newline in ["\n", "\r\n"] {
            let multiline = body.replace("<Protocol>", &format!("<Protocol>{newline}"))
                .replace("</Protocol>", &format!("{newline}</Protocol>"));
            assert!(Regex::new(r"<Protocol>(.*)</Protocol>").unwrap().captures(&multiline).is_none());
            assert_eq!(parse_activation_response(StatusCode::OK, true, Some("application/xml"), &multiline).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_error_status_even_with_certificate() {
        let (body, _) = certificate_response();
        assert!(matches!(parse_activation_response(StatusCode::FORBIDDEN, true, None, &body),
            Err(PushError::StatusError(StatusCode::FORBIDDEN))));
    }

    #[test]
    fn rejects_unexpected_origin_even_with_certificate() {
        let (body, _) = certificate_response();
        assert!(matches!(parse_activation_response(StatusCode::OK, false, None, &body),
            Err(PushError::AlbertCertParseError)));
    }

    #[test]
    fn distinguishes_missing_wrapper_and_certificate_without_accepting_either() {
        for body in ["", "<html>error</html>", "<Protocol><plist version=\"1.0\"><dict/></plist></Protocol>"] {
            assert!(matches!(parse_activation_response(StatusCode::OK, true, None, body),
                Err(PushError::AlbertCertParseError)));
        }
    }

    #[test]
    fn preserves_embedded_plist_failure() {
        // A bare string is a valid OpenStep plist; use genuinely truncated XML.
        assert!(matches!(parse_activation_response(StatusCode::OK, true, None, "<Protocol><?xml version=\"1.0\"?><plist><dict></Protocol>"),
            Err(PushError::PlistError(_))));
    }

    #[test]
    fn reports_apple_device_refusal_before_empty_protocol_certificate_error() {
        let body = "<html>ErrorKey: DEVICE_INFO_INTEGRITY_FAILED<Protocol>\n<plist version=\"1.0\"><dict/></plist>\n</Protocol></html>";
        assert!(matches!(parse_activation_response(StatusCode::OK, true, Some("text/xml"), body),
            Err(PushError::AppleAuthResponse { stage: "push-activation", status: 200,
                reason: "device-info-integrity-failed", bytes }) if bytes == body.len()));
    }

    #[test]
    fn diagnostics_cannot_emit_untrusted_body_or_header_values() {
        let summary = activation_diagnostic(StatusCode::OK, true,
            Some("application/private-secret; token=header-secret"),
            "<html>body-secret</html>", "protocol-wrapper-missing");
        assert_eq!(summary,
            "activation_response status=200 expected_origin=true media=other bytes=24 reason=protocol-wrapper-missing");
        for secret in ["private-secret", "header-secret", "body-secret", "<html>"] {
            assert!(!summary.contains(secret));
        }
    }

    #[test]
    fn structure_diagnostic_reports_types_without_server_values() {
        let parsed = Value::Dictionary(plist::Dictionary::from_iter([
            ("Error".to_owned(), Value::String("server-secret".to_owned())),
            ("ErrorCode".to_owned(), Value::Integer(123.into())),
            ("private-secret".to_owned(), Value::String("credential-secret".to_owned())),
        ]));
        assert_eq!(activation_response_shape(&parsed),
            "activation_structure root=dictionary device=missing record=missing certificate=missing iphone=missing macos=missing direct_record=missing error=string error_code=integer");
    }
}
