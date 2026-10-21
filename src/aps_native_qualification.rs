//! Feature-gated one-shot test. No activation, global keystore or live profile.
use super::{open_socket_with_protocols, APSMessage};
use crate::auth::{generate_nonce, NonceType};
use deku::prelude::*;
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Verifier,
    x509::X509,
};
use serde::Serialize;
use std::{future::Future, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize)]
pub struct QualificationReport {
    pub schema: u8,
    pub status: &'static str,
    pub local_signature_verified: bool,
    pub connect_attempts: u8,
    pub connect_written: bool,
    pub response_status: Option<u8>,
    pub token_present: bool,
    pub token_bytes: u8,
    pub port: Option<u16>,
    pub shutdown_completed: bool,
    pub private_key_exported: bool,
}

impl QualificationReport {
    pub fn failed(status: &'static str) -> Self {
        Self {
            schema: 1,
            status,
            local_signature_verified: false,
            connect_attempts: 0,
            connect_written: false,
            response_status: None,
            token_present: false,
            token_bytes: 0,
            port: None,
            shutdown_completed: false,
            private_key_exported: false,
        }
    }
}

fn certificate_key(der: &[u8]) -> Result<PKey<Public>, &'static str> {
    if !(129..=8192).contains(&der.len()) {
        return Err("certificate-size-rejected");
    }
    let certificate = X509::from_der(der).map_err(|_| "certificate-rejected")?;
    if certificate.to_der().map_err(|_| "certificate-rejected")? != der {
        return Err("certificate-rejected");
    }
    let key = certificate
        .public_key()
        .map_err(|_| "certificate-key-rejected")?;
    if key.id() != Id::RSA || ![1024, 2048, 3072, 4096].contains(&key.bits()) {
        return Err("certificate-key-rejected");
    }
    Ok(key)
}

fn verified_packet(der: &[u8], nonce: &[u8], signature: &[u8]) -> Result<Vec<u8>, &'static str> {
    if nonce.len() != 17 || nonce[0] != 0 {
        return Err("nonce-rejected");
    }
    let key = certificate_key(der)?;
    if signature.len() != (key.bits() / 8) as usize {
        return Err("signature-size-rejected");
    }
    let mut verifier =
        Verifier::new(MessageDigest::sha1(), &key).map_err(|_| "signature-rejected")?;
    verifier
        .set_rsa_padding(Padding::PKCS1)
        .map_err(|_| "signature-rejected")?;
    verifier.update(nonce).map_err(|_| "signature-rejected")?;
    if !verifier
        .verify(signature)
        .map_err(|_| "signature-rejected")?
    {
        return Err("signature-rejected");
    }
    // Identical to do_ids_signature: its RsaKey alias never leaves the process.
    // Here the signature is made by the dedicated phone, not a replacement
    // global keystore. Reuse the production raw Connect encoder and flags.
    let mut raw = APSMessage::Connect {
        flags: 0b01000001,
        certificate: Some(der.to_vec()),
        nonce: Some(nonce.to_vec()),
        signature: Some([&[1u8, 1][..], signature].concat()),
        token: None,
    }
    .to_raw();
    for field in &mut raw.body {
        field.update().map_err(|_| "packet-encoding-failed")?;
    }
    raw.update().map_err(|_| "packet-encoding-failed")?;
    raw.to_bytes().map_err(|_| "packet-encoding-failed")
}

// Bound and validate before interpreting a raw ConnectResponse. The normal
// reader handles many message kinds and assumes fields; this test needs neither
// unbounded allocations nor notification processing or panic-based field reads.
fn response_fields(body: &[u8]) -> Result<(u8, bool), &'static str> {
    if body.len() > 4096 {
        return Err("response-size-rejected");
    }
    let mut position = 0;
    let mut count = 0;
    let mut status = None;
    let mut token = false;
    while position < body.len() {
        count += 1;
        if count > 64 || body.len() - position < 3 {
            return Err("response-fields-rejected");
        }
        let id = body[position];
        let length = u16::from_be_bytes([body[position + 1], body[position + 2]]) as usize;
        position += 3;
        if length > body.len() - position {
            return Err("response-fields-rejected");
        }
        let data = &body[position..position + length];
        match id {
            1 if length == 1 && status.is_none() => status = Some(data[0]),
            3 if length == 32 && !token => token = true,
            1 | 3 => return Err("response-fields-rejected"),
            _ => (),
        }
        position += length;
    }
    Ok((status.ok_or("response-status-missing")?, token))
}

/// Exactly one APS Connect with the native certificate/signature. The caller
/// owns process and pipe deadlines. No ResourceManager or background task is
/// constructed; no token, certificate or proof appears in the returned report.
pub async fn qualify_once<S, F>(certificate: &[u8], signer: S) -> QualificationReport
where
    S: FnOnce(Vec<u8>) -> F,
    F: Future<Output = Result<Vec<u8>, &'static str>>,
{
    let mut report = QualificationReport::failed("transport-unavailable");
    if let Err(status) = certificate_key(certificate) {
        report.status = status;
        return report;
    }
    let transport = tokio::time::timeout(
        Duration::from_secs(18),
        open_socket_with_protocols(None, true),
    )
    .await;
    let (mut socket, encoder, decoder, port, _) = match transport {
        Ok(Ok(value)) => value,
        _ => return report,
    };
    report.port = Some(port);
    let operation = async {
        if encoder.is_some() || decoder.is_some() {
            return Err("framing-rejected");
        }
        if let Some(alpn) = socket.get_ref().1.alpn_protocol() {
            if alpn != b"apns-security-v3" {
                return Err("framing-rejected");
            }
        }
        let nonce = generate_nonce(NonceType::APNS);
        let signature = tokio::time::timeout(Duration::from_secs(10), signer(nonce.clone()))
            .await
            .map_err(|_| "signer-timed-out")??;
        let packet = verified_packet(certificate, &nonce, &signature)?;
        report.local_signature_verified = true;
        report.connect_attempts = 1;
        socket
            .write_all(&packet)
            .await
            .map_err(|_| "connect-write-failed")?;
        socket.flush().await.map_err(|_| "connect-write-failed")?;
        report.connect_written = true;
        let mut header = [0; 5];
        socket
            .read_exact(&mut header)
            .await
            .map_err(|_| "response-read-failed")?;
        if header[0] != 8 {
            return Err("unexpected-response-command");
        }
        let length = u32::from_be_bytes(
            header[1..]
                .try_into()
                .map_err(|_| "response-size-rejected")?,
        ) as usize;
        if length == 0 || length > 4096 {
            return Err("response-size-rejected");
        }
        let mut body = vec![0; length];
        socket
            .read_exact(&mut body)
            .await
            .map_err(|_| "response-read-failed")?;
        let (status, token) = response_fields(&body)?;
        report.response_status = Some(status);
        report.token_present = token;
        report.token_bytes = if token { 32 } else { 0 };
        Ok(if status != 0 {
            "aps-rejected"
        } else if !token {
            "aps-token-missing"
        } else {
            "accepted"
        })
    };
    report.status = match tokio::time::timeout(Duration::from_secs(18), operation).await {
        Ok(Ok(status)) => status,
        Ok(Err(status)) => status,
        Err(_) => "aps-operation-timed-out",
    };
    report.shutdown_completed = matches!(
        tokio::time::timeout(Duration::from_secs(1), socket.shutdown()).await,
        Ok(Ok(()))
    );
    drop(socket);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time, bn::BigNum, pkey::PKey, rsa::Rsa, sign::Signer, x509::X509NameBuilder,
    };

    fn fixture() -> (Vec<u8>, PKey<openssl::pkey::Private>) {
        let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "synthetic-test-only")
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build().to_der().unwrap(), key)
    }

    #[test]
    fn native_qualification_packet_reuses_raw_production_connect() {
        let (der, key) = fixture();
        let nonce = generate_nonce(NonceType::APNS);
        let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(&nonce).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let packet = verified_packet(&der, &nonce, &signature).unwrap();
        let (_, raw) = super::super::APSRawMessage::from_bytes((&packet, 0)).unwrap();
        assert_eq!(raw.command, 7);
        assert!(raw.get_field(1).is_none());
        assert_eq!(raw.get_field(12), Some(der));
        assert_eq!(raw.get_field(13), Some(nonce));
        assert_eq!(
            raw.get_field(14),
            Some([&[1u8, 1][..], signature.as_slice()].concat())
        );
        assert_eq!(raw.get_field(5), Some(0x41u32.to_be_bytes().to_vec()));
    }

    #[test]
    fn native_qualification_rejects_wrong_key_signature_and_nonce() {
        let (der, _) = fixture();
        let nonce = generate_nonce(NonceType::APNS);
        assert_eq!(
            verified_packet(&der, &nonce, &[0; 128]).unwrap_err(),
            "signature-rejected"
        );
        assert_eq!(
            verified_packet(&der, &nonce, &[0; 127]).unwrap_err(),
            "signature-size-rejected"
        );
        assert_eq!(
            verified_packet(&der, &[1; 17], &[0; 128]).unwrap_err(),
            "nonce-rejected"
        );
        assert!(certificate_key(&[]).is_err());
        assert!(certificate_key(&[0; 129]).is_err());
        assert!(certificate_key(&[0; 8193]).is_err());
        let mut trailing = der;
        trailing.push(0);
        assert!(certificate_key(&trailing).is_err());
    }

    #[test]
    fn native_qualification_strict_bounded_connect_response() {
        let mut response = vec![1, 0, 1, 0, 3, 0, 32];
        response.extend([9; 32]);
        assert_eq!(response_fields(&response), Ok((0, true)));
        assert_eq!(response_fields(&[1, 0, 1, 7]), Ok((7, false)));
        assert!(response_fields(&[3, 0, 32]).is_err());
        assert!(response_fields(&[1, 0, 0]).is_err());
        assert!(response_fields(&[1, 0, 1, 0, 1, 0, 1, 0]).is_err());
        assert!(response_fields(&[1, 0, 1, 0, 3, 0, 1, 9]).is_err());
        let mut duplicate_token = response.clone();
        duplicate_token.extend(&response[4..]);
        assert!(response_fields(&duplicate_token).is_err());
        assert!(response_fields(&[0; 4097]).is_err());
        assert!(response_fields(&[8, 0, 0].repeat(65)).is_err());
    }

    #[tokio::test]
    async fn native_qualification_invalid_certificate_never_calls_signer() {
        let report = qualify_once(&[], |_| async {
            panic!("must not sign");
            #[allow(unreachable_code)]
            Ok(vec![])
        })
        .await;
        assert_eq!(report.status, "certificate-size-rejected");
        assert!(!report.local_signature_verified);
        assert_eq!(report.connect_attempts, 0);
        assert!(!report.token_present);
    }
}
