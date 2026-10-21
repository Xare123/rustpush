use super::*;
use openssl::{asn1::Asn1Time, pkey::Private, rsa::Rsa, x509::X509NameBuilder};

const CODE: &str = "AAAA-BBBB-CCCC-DDDD";
const TIME: u64 = 1_800_000_000_000;
fn certificate() -> (Vec<u8>, PKey<Private>) {
    let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "synthetic-native-push")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (cert.build().to_der().unwrap(), key)
}
fn nonce(tag: u8) -> Vec<u8> {
    [&[tag][..], &TIME.to_be_bytes(), &[3; 8]].concat()
}
fn response(request: &NativeRequest, cert: &[u8], sig: &[u8], code: &str) -> Vec<u8> {
    let mut binding = request.hash.to_vec();
    binding.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    binding.extend_from_slice(cert);
    binding.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    binding.extend_from_slice(sig);
    serde_json::to_vec(&serde_json::json!({"ob_push_v1":{"schema":1,
        "request_sha256":STANDARD.encode(request.hash),"certificate":STANDARD.encode(cert),
        "signature":STANDARD.encode(sig),"mac":STANDARD.encode(mac(RESPONSE_DOMAIN,&binding,code).unwrap())}})).unwrap()
}
fn signature(key: &PKey<Private>, payload: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha1(), key).unwrap();
    signer.set_rsa_padding(Padding::PKCS1).unwrap();
    signer.update(payload).unwrap();
    signer.sign_to_vec().unwrap()
}

#[test]
fn discovery_is_bounded_and_does_not_put_ticket_in_url() {
    let request = NativeRequest::new(0, &[], &[], 0, None, CODE, TIME, [1; 16]).unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(request.command.strip_prefix(PREFIX).unwrap())
        .unwrap();
    assert_eq!(bytes.len(), 90);
    assert_eq!(&bytes[..2], &[1, 0]);
    assert_eq!(&bytes[2..10], &TIME.to_be_bytes());
    assert_eq!(&bytes[10..26], &[1; 16]);
    assert_eq!(&bytes[26..58], &[0; 32]);
    assert_eq!(
        &bytes[58..],
        mac(REQUEST_DOMAIN, &bytes[..58], CODE).unwrap()
    );
    assert!(!request.command.contains(CODE));
    assert!(request.command.len() < 256);
    // Independent Python hmac/sha256 reference for exactly these public bytes.
    assert_eq!(
        crate::util::encode_hex(&bytes[58..]),
        "4946de28f864169936eb6797aef9d34f568123eba1493c0f15f355a82e7bce72"
    );
}
#[test]
fn operation_and_nonce_bounds_fail_before_network() {
    let (cert, _) = certificate();
    assert!(NativeRequest::new(3, &cert, &nonce(0), 0, None, CODE, TIME, [1; 16]).is_err());
    assert!(NativeRequest::new(0, &[], &[], 0, None, CODE, TIME, [0; 16]).is_err());
    assert!(NativeRequest::new(0, &[], &[], 0, None, CODE, 0, [1; 16]).is_err());
    assert!(NativeRequest::new(0, &[], &[], 0, None, CODE, u64::MAX, [1; 16]).is_err());
    assert!(NativeRequest::new(0, &[], &[], 0, None, "not-a-ticket", TIME, [1; 16]).is_err());
    assert!(NativeRequest::new(1, &cert, &nonce(1), 0, None, CODE, TIME, [1; 16]).is_err());
    assert!(
        NativeRequest::new(1, &cert, &nonce(0), 0, None, CODE, TIME + 30_001, [1; 16]).is_err()
    );
    assert!(
        NativeRequest::new(2, &cert, &nonce(1), 5, Some([7; 20]), CODE, TIME, [1; 16]).is_err()
    );
}
#[test]
fn discover_response_requires_request_ticket_and_freshness_binding() {
    let (cert, _) = certificate();
    let request = NativeRequest::new(0, &[], &[], 0, None, CODE, TIME, [1; 16]).unwrap();
    let raw = response(&request, &cert, &[], CODE);
    assert_eq!(request.response(&raw, CODE, TIME + 1).unwrap(), cert);
    assert!(request
        .response(&raw, "EEEE-FFFF-GGGG-HHHH", TIME + 1)
        .is_err());
    assert!(request.response(&raw, CODE, TIME + 30_001).is_err());
    assert!(request.response(&raw, CODE, TIME - 1).is_err());
    let other = NativeRequest::new(0, &[], &[], 0, None, CODE, TIME, [2; 16]).unwrap();
    assert!(other.response(&raw, CODE, TIME + 1).is_err());
    assert!(request.response(&vec![0; 24_577], CODE, TIME + 1).is_err());
}
#[test]
fn both_connect_and_http_verify_exact_native_signature_with_production_prefix() {
    let (cert, key) = certificate();
    for op in [1, 2] {
        let nonce = nonce(op - 1);
        let payload = if op == 1 {
            nonce.clone()
        } else {
            crate::auth::build_payload(&nonce, &[b"id-register", b"", b"synthetic-body", &[9; 32]])
        };
        let digest = (op == 2).then(|| openssl::sha::sha1(&payload));
        let request = NativeRequest::new(
            op,
            &cert,
            &nonce,
            if op == 1 { 0 } else { 4 },
            digest,
            CODE,
            TIME,
            [1; 16],
        )
        .unwrap();
        let sig = signature(&key, &payload);
        let raw = response(&request, &cert, &sig, CODE);
        assert_eq!(
            request.response(&raw, CODE, TIME).unwrap(),
            [&[1, 1][..], &sig].concat()
        );
        let bad_sig = signature(&key, b"wrong-production-payload");
        assert!(request
            .response(&response(&request, &cert, &bad_sig, CODE), CODE, TIME)
            .is_err());
    }
}
#[test]
fn authenticated_but_wrong_certificate_or_signature_cannot_pass() {
    let (cert, key) = certificate();
    let (wrong, wrong_key) = certificate();
    let request = NativeRequest::new(1, &cert, &nonce(0), 0, None, CODE, TIME, [1; 16]).unwrap();
    let sig = signature(&wrong_key, &nonce(0));
    assert!(request
        .response(&response(&request, &wrong, &sig, CODE), CODE, TIME)
        .is_err());
    assert!(request
        .response(&response(&request, &cert, &sig, CODE), CODE, TIME)
        .is_err());
    let sig = signature(&key, &nonce(0));
    let mut value: serde_json::Value =
        serde_json::from_slice(&response(&request, &cert, &sig, CODE)).unwrap();
    value["ob_push_v1"]["private"] = serde_json::json!("unexpected");
    assert!(request
        .response(&serde_json::to_vec(&value).unwrap(), CODE, TIME)
        .is_err());
    assert!(certificate_public_key(&[cert, vec![0]].concat()).is_err());
}
#[test]
fn old_state_is_readable_and_native_runtime_secrets_never_persist() {
    let mut state: crate::APSState =
        serde_json::from_value(serde_json::json!({"token":null,"keypair":null})).unwrap();
    assert!(state.native_push.is_none());
    assert!(state.native_transport.is_none());
    let (cert, _) = certificate();
    state.native_push = Some(NativePushIdentity {
        certificate: cert,
        device_id: "synthetic-phone".into(),
        device_uuid: "synthetic-client".into(),
    });
    state.native_transport = Some(NativePushTransport {
        host: "https://relay.example".into(),
        code: CODE.into(),
        beeper_token: Some("synthetic-secret-never-persist".into()),
        device_id: "synthetic-phone".into(),
        device_uuid: "synthetic-client".into(),
    });
    assert!(state.has_push_identity());
    let mut encoded=Vec::new();
    plist::to_writer_xml(&mut encoded,&state).unwrap();
    let raw=String::from_utf8(encoded).unwrap();
    assert!(!raw.contains(CODE));
    assert!(!raw.contains("synthetic-secret-never-persist"));
    assert!(!raw.contains("native_transport"));
    let restored: crate::APSState = plist::from_bytes(raw.as_bytes()).unwrap();
    assert!(restored.has_push_identity());
    assert!(restored.native_transport.is_none());
    assert!(restored
        .native_push
        .as_ref()
        .unwrap()
        .same_owner(state.native_push.as_ref().unwrap()));
    let mut wrong = state.native_transport.clone().unwrap();
    wrong.device_uuid = "another-client".into();
    assert!(!restored.native_push.as_ref().unwrap().matches(&wrong));
}

#[tokio::test]
async fn restored_native_state_requires_bound_transport_and_never_uses_a_software_alias() {
    let (cert,_)=certificate();
    let mut state=crate::APSState::default();
    state.native_push=Some(NativePushIdentity{certificate:cert.clone(),device_id:"synthetic-phone".into(),device_uuid:"synthetic-client".into()});
    assert!(state.has_push_identity());
    assert!(state.sign_push_connect(&nonce(0)).await.is_err());
    assert!(state.sign_push_http(&nonce(1),"id-register",b"fixture").await.is_err());
    state.keypair=Some(crate::util::KeyPairNew{cert,private:keystore::RsaKey("never-access-this-alias".into())});
    assert!(!state.has_push_identity());
    assert!(state.sign_push_connect(&nonce(0)).await.is_err());
    assert!(state.sign_push_http(&nonce(1),"id-register",b"fixture").await.is_err());
}
