use super::*;
use crate::auth::{parse_apple_delegates, parse_auth_certificate};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
};

struct Server {
    release: mpsc::Sender<()>,
    task: Option<thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(task) = self.task.take() {
            task.join().unwrap();
        }
    }
}

async fn response(
    status: u16,
    body: &[u8],
    declared: Option<usize>,
    stall: bool,
) -> (Response, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let (release, stop) = mpsc::channel();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n").unwrap();
        if let Some(length) = declared {
            write!(stream, "Content-Length: {length}\r\n").unwrap();
        }
        write!(stream, "\r\n").unwrap();
        // Body limit tests may close the client as soon as headers arrive.
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        if stall {
            let _ = stop.recv_timeout(Duration::from_secs(5));
        }
    });
    let server = Server {
        release,
        task: Some(task),
    };
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://{address}/synthetic-auth"))
        .send()
        .await
        .unwrap();
    (response, server)
}

fn plist_bytes(value: Value, binary: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if binary {
        value.to_writer_binary(&mut bytes).unwrap();
    } else {
        value.to_writer_xml(&mut bytes).unwrap();
    }
    bytes
}

fn dictionary(entries: &[(&str, Value)]) -> Value {
    Value::Dictionary(
        entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect(),
    )
}

fn assert_failure(error: PushError, stage: &str, status: u16, reason: &str) {
    let rendered = error.to_string();
    match error {
        PushError::AppleAuthResponse {
            stage: actual_stage,
            status: actual_status,
            reason: actual_reason,
            ..
        } => {
            assert_eq!(actual_stage, stage);
            assert_eq!(actual_status, status);
            assert_eq!(actual_reason, reason);
        }
        other => panic!("expected classified response error, got {other:?}"),
    }
    assert!(!rendered.contains("secret@example.test"));
    assert!(!rendered.contains("session-secret"));
    assert!(!rendered.contains("123456"));
}

#[tokio::test]
async fn empty_response_reproduces_old_eof_and_is_now_classified() {
    let old_error = plist::from_bytes::<Value>(b"").unwrap_err().to_string();
    assert!(old_error.contains("UnexpectedEof"), "{old_error}");
    for status in [200, 204, 401, 403, 503] {
        let (response, _server) = response(status, b"", Some(0), false).await;
        let error = AuthResponse::read("icloud-delegates", response)
            .await
            .err()
            .unwrap();
        assert_failure(error, "icloud-delegates", status, "empty-body");
    }
}

#[tokio::test]
async fn binary_and_xml_certificates_preserve_exact_bytes() {
    let cert = vec![0, 255, 128, 13, 0, 254, 42];
    for binary in [false, true] {
        let bytes = plist_bytes(
            dictionary(&[("status", 0.into()), ("cert", Value::Data(cert.clone()))]),
            binary,
        );
        if binary {
            let lossy = String::from_utf8_lossy(&bytes);
            assert!(plist::from_bytes::<Value>(lossy.as_bytes()).is_err());
        }
        let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("ids-auth-certificate", response)
            .await
            .unwrap();
        assert_eq!(parse_auth_certificate(&parsed).unwrap(), cert);
    }
}

#[tokio::test]
async fn binary_and_xml_delegate_login_remain_supported() {
    for binary in [false, true] {
        let bytes = plist_bytes(
            dictionary(&[
                ("status", 0.into()),
                (
                    "delegates",
                    dictionary(&[(
                        "com.apple.private.ids",
                        dictionary(&[
                            ("status", 0.into()),
                            (
                                "service-data",
                                dictionary(&[
                                    ("profile-id", "synthetic-profile".into()),
                                    ("auth-token", "session-secret".into()),
                                ]),
                            ),
                        ]),
                    )]),
                ),
            ]),
            binary,
        );
        let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("icloud-delegates", response)
            .await
            .unwrap();
        let delegates = parse_apple_delegates(&parsed).unwrap();
        assert_eq!(delegates.ids.unwrap().profile_id, "synthetic-profile");
        assert!(delegates.mobileme.is_none());
    }
}

#[tokio::test]
async fn malformed_body_is_classified_without_disclosing_content() {
    for status in [200, 403, 503] {
        // plist's ASCII parser can interpret an HTML document as a string.
        // A non-dictionary root must still be rejected without echoing it.
        for (bytes, reason) in [
            (
                b"<html>secret@example.test session-secret 123456</html>".as_slice(),
                "invalid-root",
            ),
            (b"bplist00".as_slice(), "invalid-plist"),
            (b"<plist><dict>".as_slice(), "invalid-plist"),
        ] {
            let (response, _server) = response(status, bytes, Some(bytes.len()), false).await;
            assert_failure(
                AuthResponse::read("icloud-delegates", response)
                    .await
                    .err()
                    .unwrap(),
                "icloud-delegates",
                status,
                reason,
            );
        }
    }
}

#[tokio::test]
async fn root_must_be_a_dictionary() {
    let bytes = plist_bytes(Value::Array(vec!["session-secret".into()]), true);
    let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
    assert_failure(
        AuthResponse::read("icloud-delegates", response)
            .await
            .err()
            .unwrap(),
        "icloud-delegates",
        200,
        "invalid-root",
    );
}

#[tokio::test]
async fn structured_error_without_certificate_preserves_service_rejection() {
    for status in [200, 401, 500] {
        let bytes = plist_bytes(dictionary(&[("status", 6005.into())]), true);
        let (response, _server) = response(status, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("ids-auth-certificate", response)
            .await
            .unwrap();
        assert!(matches!(
            parse_auth_certificate(&parsed),
            Err(PushError::CertError(_))
        ));
    }
}

#[tokio::test]
async fn terms_and_unauthorized_delegate_errors_remain_actionable() {
    for localized in ["UNAUTHORIZED", "MOBILEME_TERMS_OF_SERVICE_UPDATE"] {
        let bytes = plist_bytes(dictionary(&[("localizedError", localized.into())]), false);
        let (response, _server) = response(401, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("icloud-delegates", response)
            .await
            .unwrap();
        match (localized, parse_apple_delegates(&parsed)) {
            ("UNAUTHORIZED", Err(PushError::UnauthorizedAccountError)) => {}
            (_, Err(PushError::MobileMeError(code, _))) => assert_eq!(code, localized),
            _ => panic!("service rejection lost"),
        }
    }
}

#[tokio::test]
async fn non_success_http_never_accepts_success_plist() {
    for status in [302, 403, 503] {
        let bytes = plist_bytes(
            dictionary(&[("status", 0.into()), ("cert", Value::Data(vec![1]))]),
            false,
        );
        let (response, _server) = response(status, &bytes, Some(bytes.len()), false).await;
        assert_failure(
            AuthResponse::read("ids-auth-certificate", response)
                .await
                .err()
                .unwrap(),
            "ids-auth-certificate",
            status,
            "http-error",
        );
    }
}

#[tokio::test]
async fn localized_error_cannot_smuggle_success_certificate() {
    for status in [200, 403] {
        let bytes = plist_bytes(
            dictionary(&[
                ("status", 0.into()),
                ("cert", Value::Data(vec![1])),
                ("localizedError", "UNAUTHORIZED".into()),
            ]),
            false,
        );
        let (response, _server) = response(status, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("ids-auth-certificate", response)
            .await
            .unwrap();
        assert_failure(
            parse_auth_certificate(&parsed).err().unwrap(),
            "ids-auth-certificate",
            status,
            if status == 200 {
                "unexpected-certificate-error"
            } else {
                "http-error"
            },
        );
    }
}

#[tokio::test]
async fn missing_or_wrong_status_is_not_success() {
    for entries in [vec![], vec![("status", "0".into())]] {
        let bytes = plist_bytes(dictionary(&entries), false);
        let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("icloud-delegates", response)
            .await
            .unwrap();
        assert_failure(
            parse_apple_delegates(&parsed).err().unwrap(),
            "icloud-delegates",
            200,
            "invalid-status",
        );
    }
}

#[tokio::test]
async fn missing_delegates_is_not_a_panic() {
    let bytes = plist_bytes(dictionary(&[("status", 0.into())]), true);
    let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
    let parsed = AuthResponse::read("icloud-delegates", response)
        .await
        .unwrap();
    assert_failure(
        parse_apple_delegates(&parsed).err().unwrap(),
        "icloud-delegates",
        200,
        "invalid-delegates",
    );
}

#[tokio::test]
async fn failing_delegate_status_cannot_supply_success_data() {
    let bytes = plist_bytes(
        dictionary(&[
            ("status", 0.into()),
            (
                "delegates",
                dictionary(&[(
                    "com.apple.private.ids",
                    dictionary(&[("status", 6005.into()), ("service-data", dictionary(&[]))]),
                )]),
            ),
        ]),
        false,
    );
    let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
    let parsed = AuthResponse::read("icloud-delegates", response)
        .await
        .unwrap();
    assert!(matches!(
        parse_apple_delegates(&parsed),
        Err(PushError::DelegateLoginFailed(_, 6005, _))
    ));
}

#[tokio::test]
async fn missing_or_empty_certificates_are_not_accepted() {
    for empty in [false, true] {
        let mut entries = vec![("status", 0.into())];
        if empty {
            entries.push(("cert", Value::Data(vec![])));
        }
        let bytes = plist_bytes(dictionary(&entries), true);
        let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("ids-auth-certificate", response)
            .await
            .unwrap();
        assert_failure(
            parse_auth_certificate(&parsed).err().unwrap(),
            "ids-auth-certificate",
            200,
            if empty {
                "empty-certificate"
            } else {
                "missing-certificate"
            },
        );
    }
}

#[tokio::test]
async fn declared_body_size_is_bounded_before_reading() {
    let (response, _server) = response(200, b"", Some(MAX_AUTH_RESPONSE_BYTES + 1), true).await;
    assert_failure(
        AuthResponse::read("icloud-delegates", response)
            .await
            .err()
            .unwrap(),
        "icloud-delegates",
        200,
        "body-too-large",
    );
}

#[tokio::test]
async fn body_without_length_is_incrementally_bounded() {
    let (response, _server) =
        response(200, &vec![b'a'; MAX_AUTH_RESPONSE_BYTES + 1], None, true).await;
    let parsed = tokio::time::timeout(
        Duration::from_secs(2),
        AuthResponse::read("icloud-delegates", response),
    )
    .await
    .expect("must reject oversized bytes without waiting for connection close");
    assert_failure(
        parsed.err().unwrap(),
        "icloud-delegates",
        200,
        "body-too-large",
    );
}

#[tokio::test]
async fn truncated_http_body_is_not_a_plist_eof() {
    let (response, _server) = response(200, b"<plist>", Some(100), false).await;
    assert_failure(
        AuthResponse::read("icloud-delegates", response)
            .await
            .err()
            .unwrap(),
        "icloud-delegates",
        200,
        "incomplete-body",
    );
}

#[tokio::test]
async fn stalled_body_has_a_single_bounded_deadline() {
    let (response, _server) = response(200, b"<plist>", Some(100), true).await;
    assert_failure(
        AuthResponse::read_with_timeout("icloud-delegates", response, Duration::from_millis(50))
            .await
            .err()
            .unwrap(),
        "icloud-delegates",
        200,
        "body-timeout",
    );
}

#[tokio::test]
async fn service_bag_requires_an_intact_embedded_dictionary() {
    let valid = plist_bytes(
        dictionary(&[("synthetic-service", "https://example.test/service".into())]),
        true,
    );
    for (embedded, expected_error) in [
        (vec![], Some("empty-bag")),
        (b"bplist00".to_vec(), Some("invalid-bag")),
        (valid, None),
    ] {
        let bytes = plist_bytes(dictionary(&[("bag", Value::Data(embedded))]), false);
        let (response, _server) = response(200, &bytes, Some(bytes.len()), false).await;
        let parsed = AuthResponse::read("apple-service-bag", response)
            .await
            .unwrap();
        let bag = crate::util::parse_service_bag(&parsed);
        if let Some(reason) = expected_error {
            assert_failure(bag.err().unwrap(), "apple-service-bag", 200, reason);
        } else {
            assert_eq!(
                bag.unwrap()
                    .get("synthetic-service")
                    .and_then(Value::as_string),
                Some("https://example.test/service")
            );
        }
    }
}
