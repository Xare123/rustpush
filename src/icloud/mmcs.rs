use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::{
    aps::get_message,
    error::PushError,
    mmcsp::{
        self, authorize_get_response,
        authorize_put::put_data::{Chunk, FordDesc},
        authorize_put_response::{upload_target::ChunkIdentifier, UploadTarget},
        Container as ProtoContainer, FordChunk, FordChunkItem, FordItem, HttpRequest,
    },
    util::{decode_hex, encode_hex, plist_to_bin, REQWEST},
    APSConnectionResource,
};
use aes::Aes256;
use aes_siv::siv::CmacSiv;
use aes_siv::KeyInit;
use async_trait::async_trait;
use hkdf::Hkdf;
use log::{debug, info, warn};
use openssl::{
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    sha::{sha1, sha256, Sha1},
    sign::{self, Signer},
    symm::{decrypt, encrypt, Cipher},
};
use plist::Data;
use prost::Message;
use rand::{Rng, RngCore};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Body, Certificate, Client, Response,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Write};
use std::str::FromStr;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MMCSTransferData {
    pub mmcs_owner: String,
    pub mmcs_url: String,
    pub mmcs_signature_hex: String,
    pub file_size: String,
    pub decryption_key: String,
}

pub struct MMCSConfig {
    pub mme_client_info: String,
    pub user_agent: String,
    pub dataclass: &'static str,
    pub mini_ua: String,
    pub dsid: Option<String>,
    pub cloudkit_headers: HashMap<&'static str, String>,
    pub extra_1: Option<String>,
    pub extra_2: Option<String>,
}

/// Network policy for an MMCS download. The CloudKit attachment materializer
/// uses `PreauthorizedDownloadOnly`, which can issue only the exact HTTPS GETs
/// described by the CloudKit authorize response. It never calls authorizeGet,
/// follows redirects, adds an application-level retry, or sends getComplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MMCSGetNetworkPolicy {
    Standard,
    PreauthorizedDownloadOnly,
}

const MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_AUTHORIZATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS: usize = 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES: usize = 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER: usize = 8192;
const MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNKS: usize = 16384;
const MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST: usize = 128;
const MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_HEADERS: usize = 128 * 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES: usize = 8192;
const MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES: usize = 65536;
const MAX_PREAUTHORIZED_DOWNLOAD_WIRE_FIELDS: usize = 1_000_000;
const MAX_PREAUTHORIZED_DOWNLOAD_PATH_BYTES: usize = 16 * 1024;
const MAX_PREAUTHORIZED_DOWNLOAD_HEADER_NAME_BYTES: usize = 256;
const MAX_PREAUTHORIZED_DOWNLOAD_HEADER_VALUE_BYTES: usize = 16 * 1024;
const MMCS_BOUNDED_SKIP_BYTES: usize = 64 * 1024;

impl MMCSGetNetworkPolicy {
    fn sends_completion(self) -> bool {
        self == Self::Standard
    }

    fn collects_completion_receipts(self) -> bool {
        self == Self::Standard
    }
}

fn validate_download_only_chunk_request(request: &HttpRequest) -> Result<(), PushError> {
    let domain = request.domain.as_str();
    if domain.is_empty() || !domain.is_ascii() || domain.len() > 253 {
        warn!("Rejected preauthorized MMCS request at domain-shape validation");
        return Err(PushError::VerificationFailed);
    }

    let mut label_count = 0usize;
    let mut final_label = None;
    for label in domain.split('.') {
        label_count = label_count
            .checked_add(1)
            .ok_or(PushError::VerificationFailed)?;
        if label.is_empty()
            || label.len() > 63
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            warn!("Rejected preauthorized MMCS request at domain-label validation");
            return Err(PushError::VerificationFailed);
        }
        final_label = Some(label);
    }
    let final_label = final_label.ok_or(PushError::VerificationFailed)?;
    let valid_dns_name = label_count >= 2
        && final_label.bytes().any(|byte| byte.is_ascii_alphabetic())
        && !final_label.eq_ignore_ascii_case("local")
        && domain.parse::<IpAddr>().is_err();

    if request.method != "GET"
        || request.scheme != "https"
        || request.port != 443
        || !valid_dns_name
        || request.path.len() > MAX_PREAUTHORIZED_DOWNLOAD_PATH_BYTES
        || !request.path.starts_with('/')
        || request.path.starts_with("//")
        || request
            .path
            .chars()
            .any(|character| character.is_ascii_control() || character == '\\')
    {
        warn!("Rejected preauthorized MMCS request at closed-GET-shape validation");
        return Err(PushError::VerificationFailed);
    }

    // Header names in authorize responses have varied across MMCS revisions,
    // so retain Apple authorization headers while rejecting every routing,
    // method-tunnelling, hop-by-hop, authority, and framing control that could
    // change the closed GET request shape.
    if request.headers.len() > MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST {
        warn!("Rejected preauthorized MMCS request at header-count validation");
        return Err(PushError::VerificationFailed);
    }
    let mut saw_redundant_host = false;
    for header in &request.headers {
        if header.name.len() > MAX_PREAUTHORIZED_DOWNLOAD_HEADER_NAME_BYTES
            || header.value.len() > MAX_PREAUTHORIZED_DOWNLOAD_HEADER_VALUE_BYTES
        {
            warn!("Rejected preauthorized MMCS request at header-size validation");
            return Err(PushError::VerificationFailed);
        }
        // Apple includes a redundant Host header in some preauthorized MMCS
        // GET descriptors. Never forward that server-supplied authority. It
        // is admissible only once, only when it exactly names the already
        // validated URL authority, and reqwest reconstructs it from that URL.
        if header.name.eq_ignore_ascii_case("host") {
            let exact_domain = header.value.eq_ignore_ascii_case(domain);
            let exact_domain_and_port = header
                .value
                .strip_suffix(":443")
                .is_some_and(|host| host.eq_ignore_ascii_case(domain));
            if saw_redundant_host || (!exact_domain && !exact_domain_and_port) {
                warn!("Rejected preauthorized MMCS request at header-control validation");
                return Err(PushError::VerificationFailed);
            }
            saw_redundant_host = true;
            continue;
        }
        if download_only_header_changes_request_shape(&header.name) {
            warn!("Rejected preauthorized MMCS request at header-control validation");
            return Err(PushError::VerificationFailed);
        }
        if HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || HeaderValue::from_str(&header.value).is_err()
        {
            warn!("Rejected preauthorized MMCS request at header-syntax validation");
            return Err(PushError::VerificationFailed);
        }
    }

    Ok(())
}

fn download_only_header_changes_request_shape(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "content-length"
            | "expect"
            | "forwarded"
            | "via"
            | "x-real-ip"
            | "x-client-ip"
            | "x-cluster-client-ip"
            | "authority"
            | "x-authority"
            | "x-host"
            | "destination"
            | "x-http-destinationurl"
            | "max-forwards"
            | "proxy"
            | "x-original-host"
            | "x-original-url"
            | "x-original-uri"
            | "x-rewrite-url"
            | "x-original-method"
            | "x-method-override"
            | "x-apple-put-complete-at-edge-version"
    ) || name.starts_with("x-forwarded-")
        || name == "x-forwarded"
        || name.starts_with("proxy-")
        || name == "x-http-method"
        || name.starts_with("x-http-method-")
        || name == "x-method"
        || name.starts_with("x-method-")
        || name.starts_with("x-original-")
        || name.starts_with("x-rewrite-")
        || name.starts_with("x-envoy-original-")
        || name.starts_with("x-amzn-remapped-")
}

fn is_public_download_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_download_ipv4(address),
        IpAddr::V6(address) => is_public_download_ipv6(address),
    }
}

fn is_public_download_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240)
}

fn is_public_download_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_download_ipv4(mapped);
    }

    let segments = address.segments();
    let well_known_nat64 = segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
    let well_known_nat64_embeds_public_ipv4 = if well_known_nat64 {
        let [a, b] = segments[6].to_be_bytes();
        let [c, d] = segments[7].to_be_bytes();
        is_public_download_ipv4(Ipv4Addr::new(a, b, c, d))
    } else {
        true
    };
    let global_unicast = (segments[0] & 0xe000) == 0x2000 || well_known_nat64;
    let ietf_protocol_assignment = segments[0] == 0x2001 && segments[1] < 0x0200;
    let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0);
    let local_nat64 = segments[0] == 0x64 && segments[1] == 0xff9b && segments[2] == 1;
    let discard_only = segments[..4] == [0x100, 0, 0, 0];
    let six_to_four_non_public = if segments[0] == 0x2002 {
        let [a, b] = segments[1].to_be_bytes();
        let [c, d] = segments[2].to_be_bytes();
        !is_public_download_ipv4(Ipv4Addr::new(a, b, c, d))
    } else {
        false
    };

    global_unicast
        && !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && (segments[0] & 0xfe00) != 0xfc00
        && (segments[0] & 0xfe00) != 0xfe00
        && segments[..4] != [0, 0, 0, 0]
        && !local_nat64
        && well_known_nat64_embeds_public_ipv4
        && !discard_only
        && !ietf_protocol_assignment
        && !documentation
        && segments[0] != 0x5f00
        && !six_to_four_non_public
}

fn validate_download_only_resolved_addresses(addresses: &[SocketAddr]) -> Result<(), PushError> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| address.port() != 443 || !is_public_download_address(address.ip()))
    {
        return Err(PushError::VerificationFailed);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AuthorizationWireMessage {
    Root,
    ResponseData,
    Container,
    ChunkWrapper,
    ChunkMeta,
    EncryptionMeta,
    EncryptedChunks,
    ChunkReferences,
    ChunkReference,
    HttpRequest,
    HttpHeader,
    Error,
    ErrorDetail,
}

#[derive(Default)]
struct AuthorizationWireCounts {
    fields: usize,
    containers: usize,
    references: usize,
    chunks: usize,
    headers: usize,
    chunk_references: usize,
}

#[derive(Clone, Copy)]
struct ProtobufWireField<'a> {
    number: u32,
    wire_type: u8,
    length_delimited: Option<&'a [u8]>,
}

fn read_canonical_protobuf_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, PushError> {
    let mut value = 0u64;
    for index in 0..10usize {
        let byte = *bytes.get(*cursor).ok_or(PushError::VerificationFailed)?;
        *cursor = cursor.checked_add(1).ok_or(PushError::VerificationFailed)?;
        if index == 9 && byte > 1 {
            return Err(PushError::VerificationFailed);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err(PushError::VerificationFailed);
            }
            return Ok(value);
        }
    }
    Err(PushError::VerificationFailed)
}

fn read_protobuf_wire_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
) -> Result<ProtobufWireField<'a>, PushError> {
    let key = read_canonical_protobuf_varint(bytes, cursor)?;
    let field_number = key >> 3;
    if field_number == 0 || field_number > 0x1fff_ffff {
        return Err(PushError::VerificationFailed);
    }
    let wire_type = (key & 0x07) as u8;
    let length_delimited = match wire_type {
        0 => {
            read_canonical_protobuf_varint(bytes, cursor)?;
            None
        }
        1 => {
            *cursor = cursor
                .checked_add(8)
                .filter(|end| *end <= bytes.len())
                .ok_or(PushError::VerificationFailed)?;
            None
        }
        2 => {
            let length = usize::try_from(read_canonical_protobuf_varint(bytes, cursor)?)
                .map_err(|_| PushError::VerificationFailed)?;
            let end = cursor
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(PushError::VerificationFailed)?;
            let value = bytes
                .get(*cursor..end)
                .ok_or(PushError::VerificationFailed)?;
            *cursor = end;
            Some(value)
        }
        5 => {
            *cursor = cursor
                .checked_add(4)
                .filter(|end| *end <= bytes.len())
                .ok_or(PushError::VerificationFailed)?;
            None
        }
        _ => return Err(PushError::VerificationFailed),
    };

    Ok(ProtobufWireField {
        number: u32::try_from(field_number).map_err(|_| PushError::VerificationFailed)?,
        wire_type,
        length_delimited,
    })
}

fn require_wire_type(field: ProtobufWireField<'_>, wire_type: u8) -> Result<(), PushError> {
    if field.wire_type != wire_type {
        return Err(PushError::VerificationFailed);
    }
    Ok(())
}

fn preflight_nested_authorization_message(
    field: ProtobufWireField<'_>,
    message: AuthorizationWireMessage,
    counts: &mut AuthorizationWireCounts,
) -> Result<(), PushError> {
    require_wire_type(field, 2)?;
    preflight_authorization_message(
        field
            .length_delimited
            .ok_or(PushError::VerificationFailed)?,
        message,
        counts,
    )
}

fn increment_wire_count(count: &mut usize, maximum: usize) -> Result<(), PushError> {
    *count = count
        .checked_add(1)
        .filter(|count| *count <= maximum)
        .ok_or(PushError::VerificationFailed)?;
    Ok(())
}

fn preflight_authorization_message(
    bytes: &[u8],
    message: AuthorizationWireMessage,
    counts: &mut AuthorizationWireCounts,
) -> Result<(), PushError> {
    let mut cursor = 0usize;
    let mut local_chunks = 0usize;
    let mut local_headers = 0usize;
    let mut local_chunk_references = 0usize;
    let mut local_ford_references = 0usize;

    while cursor < bytes.len() {
        let field = read_protobuf_wire_field(bytes, &mut cursor)?;
        increment_wire_count(&mut counts.fields, MAX_PREAUTHORIZED_DOWNLOAD_WIRE_FIELDS)?;

        match (message, field.number) {
            (AuthorizationWireMessage::Root, 1) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::ResponseData,
                counts,
            )?,
            (AuthorizationWireMessage::Root, 2) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::Error,
                counts,
            )?,
            (AuthorizationWireMessage::Root, 4) => require_wire_type(field, 0)?,

            (AuthorizationWireMessage::ResponseData, 1) => {
                increment_wire_count(
                    &mut counts.containers,
                    MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS,
                )?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::Container,
                    counts,
                )?;
            }
            (AuthorizationWireMessage::ResponseData, 2) => {
                increment_wire_count(
                    &mut counts.references,
                    MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES,
                )?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::ChunkReferences,
                    counts,
                )?;
            }

            (AuthorizationWireMessage::Container, 1) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::HttpRequest,
                counts,
            )?,
            (AuthorizationWireMessage::Container, 3 | 4) => require_wire_type(field, 2)?,
            (AuthorizationWireMessage::Container, 5) => {
                increment_wire_count(
                    &mut local_chunks,
                    MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER,
                )?;
                increment_wire_count(&mut counts.chunks, MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNKS)?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::ChunkWrapper,
                    counts,
                )?;
            }

            (AuthorizationWireMessage::ChunkWrapper, 1) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::ChunkMeta,
                counts,
            )?,
            (AuthorizationWireMessage::ChunkWrapper, 2) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::EncryptionMeta,
                counts,
            )?,

            (AuthorizationWireMessage::ChunkMeta, 1 | 2) => require_wire_type(field, 2)?,
            (AuthorizationWireMessage::ChunkMeta, 3 | 4) => require_wire_type(field, 0)?,

            (AuthorizationWireMessage::EncryptionMeta, 1 | 2) => require_wire_type(field, 0)?,
            (AuthorizationWireMessage::EncryptionMeta, 3) => {
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::EncryptedChunks,
                    counts,
                )?
            }
            (AuthorizationWireMessage::EncryptedChunks, 1 | 2) => require_wire_type(field, 2)?,

            (AuthorizationWireMessage::ChunkReferences, 1 | 3) => require_wire_type(field, 2)?,
            (AuthorizationWireMessage::ChunkReferences, 2) => {
                increment_wire_count(
                    &mut local_chunk_references,
                    MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES,
                )?;
                increment_wire_count(
                    &mut counts.chunk_references,
                    MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES,
                )?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::ChunkReference,
                    counts,
                )?;
            }
            (AuthorizationWireMessage::ChunkReferences, 5) => require_wire_type(field, 0)?,
            (AuthorizationWireMessage::ChunkReferences, 6) => {
                increment_wire_count(&mut local_ford_references, 1)?;
                increment_wire_count(
                    &mut counts.chunk_references,
                    MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES,
                )?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::ChunkReference,
                    counts,
                )?;
            }
            (AuthorizationWireMessage::ChunkReference, 1 | 2) => require_wire_type(field, 0)?,

            (AuthorizationWireMessage::HttpRequest, 1 | 3 | 4 | 5 | 6 | 7 | 9) => {
                require_wire_type(field, 2)?
            }
            (AuthorizationWireMessage::HttpRequest, 2 | 11 | 13) => require_wire_type(field, 0)?,
            (AuthorizationWireMessage::HttpRequest, 8) => {
                increment_wire_count(
                    &mut local_headers,
                    MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST,
                )?;
                increment_wire_count(
                    &mut counts.headers,
                    MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_HEADERS,
                )?;
                preflight_nested_authorization_message(
                    field,
                    AuthorizationWireMessage::HttpHeader,
                    counts,
                )?;
            }
            (AuthorizationWireMessage::HttpHeader, 1 | 2) => require_wire_type(field, 2)?,

            (AuthorizationWireMessage::Error, 2) => preflight_nested_authorization_message(
                field,
                AuthorizationWireMessage::ErrorDetail,
                counts,
            )?,
            (AuthorizationWireMessage::ErrorDetail, 3) => require_wire_type(field, 2)?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_preauthorized_authorization_body(body: &[u8]) -> Result<(), PushError> {
    if body.len() > MAX_PREAUTHORIZED_DOWNLOAD_AUTHORIZATION_BYTES {
        return Err(PushError::VerificationFailed);
    }
    preflight_authorization_message(
        body,
        AuthorizationWireMessage::Root,
        &mut AuthorizationWireCounts::default(),
    )
}

fn record_preauthorized_response_bytes(
    counter: &AtomicU64,
    byte_count: usize,
) -> Result<(), PushError> {
    let byte_count = u64::try_from(byte_count).map_err(|_| PushError::VerificationFailed)?;
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current
                .checked_add(byte_count)
                .filter(|total| *total <= MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES)
        })
        .map(|_| ())
        .map_err(|_| PushError::VerificationFailed)
}

async fn build_pinned_download_only_client(domain: &str) -> Result<Client, PushError> {
    let mut addresses = tokio::net::lookup_host((domain, 443))
        .await
        .map_err(|_| PushError::VerificationFailed)?
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    validate_download_only_resolved_addresses(&addresses)?;
    let normalized_domain = domain.to_ascii_lowercase();

    let certificates = [
        Certificate::from_pem(include_bytes!(
            "../../certs/root/profileidentity.ess.apple.com.cert"
        ))?,
        Certificate::from_pem(include_bytes!("../../certs/root/init.ess.apple.com.cert"))?,
    ];
    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        "Accept-Language",
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    let mut builder = Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .default_headers(default_headers)
        .http1_title_case_headers()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&normalized_domain, &addresses);
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder.build()?)
}

fn select_source_chunks(
    chunks: Vec<ChunkDesc>,
    network_policy: MMCSGetNetworkPolicy,
    required_chunk_ids: &HashSet<[u8; 21]>,
) -> Vec<ChunkDesc> {
    if network_policy == MMCSGetNetworkPolicy::Standard {
        return chunks;
    }
    chunks
        .into_iter()
        .filter(|chunk| required_chunk_ids.contains(&chunk.id))
        .collect()
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PushError> {
    bytes.try_into().map_err(|_| PushError::VerificationFailed)
}

fn response_chunk<'a>(
    containers: &'a [ProtoContainer],
    container_index: u32,
    chunk_index: u32,
) -> Result<&'a mmcsp::container::ChunkWrapper, PushError> {
    containers
        .get(container_index as usize)
        .and_then(|container| container.chunks.get(chunk_index as usize))
        .ok_or(PushError::VerificationFailed)
}

fn validate_preauthorized_container_segment(
    offset: u64,
    size: u64,
    previous_end: &mut u64,
) -> Result<(), PushError> {
    let end = offset
        .checked_add(size)
        .filter(|end| *end <= MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES)
        .ok_or(PushError::VerificationFailed)?;
    if offset < *previous_end {
        return Err(PushError::VerificationFailed);
    }
    *previous_end = end;
    Ok(())
}

fn validate_preauthorized_download_response(
    response: &authorize_get_response::F1,
    requested_files: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<(), PushError> {
    if response.containers.is_empty()
        || response.references.is_empty()
        || requested_files.is_empty()
        || response.containers.len() > MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS
        || response.references.len() > MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES
        || requested_files.len() > MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES
    {
        warn!("Rejected preauthorized MMCS response at cardinality validation");
        return Err(PushError::VerificationFailed);
    }
    if requested_files
        .iter()
        .any(|(checksum, _)| checksum.len() != 21)
        || response
            .references
            .iter()
            .any(|reference| reference.file_checksum.len() != 21)
    {
        warn!("Rejected preauthorized MMCS response at file-checksum-shape validation");
        return Err(PushError::VerificationFailed);
    }

    let mut aggregate_chunk_bytes = 0u64;
    let mut total_chunks = 0usize;
    for container in &response.containers {
        validate_download_only_chunk_request(
            container
                .request
                .as_ref()
                .ok_or(PushError::VerificationFailed)?,
        )?;
        if container.chunks.is_empty()
            || container.chunks.len() > MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER
        {
            warn!("Rejected preauthorized MMCS response at container-chunk-count validation");
            return Err(PushError::VerificationFailed);
        }
        total_chunks = total_chunks
            .checked_add(container.chunks.len())
            .filter(|count| *count <= MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNKS)
            .ok_or(PushError::VerificationFailed)?;
        let mut previous_end = 0u64;
        for chunk in &container.chunks {
            match (&chunk.meta, &chunk.encryption) {
                (Some(meta), None) => {
                    fixed_bytes::<21>(&meta.checksum)?;
                    if meta.size > MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES {
                        warn!("Rejected preauthorized MMCS response at chunk-size validation");
                        return Err(PushError::VerificationFailed);
                    }
                    validate_preauthorized_container_segment(
                        meta.offset,
                        meta.size,
                        &mut previous_end,
                    )?;
                    aggregate_chunk_bytes = aggregate_chunk_bytes
                        .checked_add(meta.size)
                        .filter(|total| *total <= MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES)
                        .ok_or(PushError::VerificationFailed)?;
                    usize::try_from(meta.size).map_err(|_| PushError::VerificationFailed)?;
                    usize::try_from(meta.offset).map_err(|_| PushError::VerificationFailed)?;
                    if let Some(key) = &meta.encryption_key {
                        fixed_bytes::<17>(key)?;
                    }
                }
                (None, Some(encryption)) => {
                    let encryption_size = u64::from(encryption.size);
                    if encryption_size > MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES {
                        warn!("Rejected preauthorized MMCS response at Ford-size validation");
                        return Err(PushError::VerificationFailed);
                    }
                    validate_preauthorized_container_segment(
                        u64::from(encryption.offset),
                        encryption_size,
                        &mut previous_end,
                    )?;
                    aggregate_chunk_bytes = aggregate_chunk_bytes
                        .checked_add(encryption_size)
                        .filter(|total| *total <= MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES)
                        .ok_or(PushError::VerificationFailed)?;
                    let for_chunks = encryption
                        .for_chunks
                        .as_ref()
                        .ok_or(PushError::VerificationFailed)?;
                    fixed_bytes::<21>(&for_chunks.container)?;
                    fixed_bytes::<21>(&for_chunks.keys_container)?;
                }
                _ => {
                    warn!("Rejected preauthorized MMCS response at chunk-kind validation");
                    return Err(PushError::VerificationFailed);
                }
            }
        }
    }

    let mut matched = vec![false; requested_files.len()];
    let mut aggregate_chunk_references = 0usize;
    for reference in &response.references {
        if reference.chunk_references.is_empty()
            || reference.chunk_references.len() > MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES
        {
            warn!("Rejected preauthorized MMCS response at chunk-reference-count validation");
            return Err(PushError::VerificationFailed);
        }
        aggregate_chunk_references = aggregate_chunk_references
            .checked_add(reference.chunk_references.len())
            .and_then(|count| count.checked_add(usize::from(reference.ford_reference.is_some())))
            .filter(|count| *count <= MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES)
            .ok_or(PushError::VerificationFailed)?;
        for chunk_reference in &reference.chunk_references {
            let chunk = response_chunk(
                &response.containers,
                chunk_reference.container_index,
                chunk_reference.chunk_index,
            )?;
            let meta = chunk.meta.as_ref().ok_or(PushError::VerificationFailed)?;
            fixed_bytes::<21>(&meta.checksum)?;
        }
        if let Some(ford_reference) = &reference.ford_reference {
            let chunk = response_chunk(
                &response.containers,
                ford_reference.container_index,
                ford_reference.chunk_index,
            )?;
            let encryption = chunk
                .encryption
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            let for_chunks = encryption
                .for_chunks
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            fixed_bytes::<21>(&for_chunks.container)?;
            fixed_bytes::<21>(&for_chunks.keys_container)?;
        }
        let Some(requested_index) = requested_files
            .iter()
            .position(|(checksum, _)| checksum == &reference.file_checksum)
        else {
            // CloudKit can bundle authorization references for sibling assets
            // in the same response. They remain fully shape-validated above,
            // but the download-only matcher later selects chunks solely for
            // the explicitly requested checksum. Requiring every bundled
            // reference to be requested rejected valid multi-asset responses.
            continue;
        };
        if matched
            .get(requested_index)
            .copied()
            .ok_or(PushError::VerificationFailed)?
        {
            warn!("Rejected preauthorized MMCS response at duplicate-file-reference validation");
            return Err(PushError::VerificationFailed);
        }
        let requested_key = requested_files
            .get(requested_index)
            .and_then(|(_, key)| key.as_deref());
        // CloudKit may carry a protection key on an asset whose current MMCS
        // response uses only ordinary checksum-authenticated chunks. The
        // standard reader ignores that unused key. A Ford reference, however,
        // is never admissible without the exact requested protection key.
        if reference.ford_reference.is_some() && requested_key.is_none() {
            warn!("Rejected preauthorized MMCS response at Ford-key-presence validation");
            return Err(PushError::VerificationFailed);
        }
        if let (Some(key), Some(ford_reference)) = (requested_key, &reference.ford_reference) {
            let expected_ford_reference = ford_key_signature(key)?;
            let chunk = response_chunk(
                &response.containers,
                ford_reference.container_index,
                ford_reference.chunk_index,
            )?;
            let encryption = chunk
                .encryption
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            let for_chunks = encryption
                .for_chunks
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            if fixed_bytes::<21>(&for_chunks.keys_container)? != expected_ford_reference {
                warn!("Rejected preauthorized MMCS response at Ford-key-binding validation");
                return Err(PushError::VerificationFailed);
            }
        }
        *matched
            .get_mut(requested_index)
            .ok_or(PushError::VerificationFailed)? = true;
    }

    if matched.iter().any(|matched| !matched) {
        warn!("Rejected preauthorized MMCS response at complete-file-match validation");
        return Err(PushError::VerificationFailed);
    }
    Ok(())
}

fn ford_key_signature(key: &[u8]) -> Result<[u8; 21], PushError> {
    if key.is_empty() {
        return Err(PushError::VerificationFailed);
    }
    let mut signature = [0u8; 21];
    signature[0] = 0x01;
    signature[1..].copy_from_slice(&sha1(key));
    Ok(signature)
}

fn decode_ford_item(ford: &[u8], key: &[u8]) -> Result<FordItem, PushError> {
    if key.is_empty() || ford.len() <= 17 {
        return Err(PushError::VerificationFailed);
    }
    let version = [*ford.first().ok_or(PushError::VerificationFailed)?];
    let iv = ford.get(1..17).ok_or(PushError::VerificationFailed)?;
    let ciphertext = ford.get(17..).ok_or(PushError::VerificationFailed)?;

    let hk = Hkdf::<Sha256>::new(Some(b"PCSMMCS2"), key);
    let mut result = [0u8; 64];
    hk.expand(&[], &mut result)
        .map_err(|_| PushError::VerificationFailed)?;
    let mut cipher =
        CmacSiv::<Aes256>::new_from_slice(&result).map_err(|_| PushError::VerificationFailed)?;
    let data = cipher
        .decrypt::<&[&[u8]], &&[u8]>(&[iv, &version], &ciphertext)
        .map_err(|_| PushError::VerificationFailed)?;
    require_ford_item(FordChunk::decode(Cursor::new(data))?)
}

fn require_ford_item(chunk: FordChunk) -> Result<FordItem, PushError> {
    chunk.item.ok_or(PushError::VerificationFailed)
}

fn add_ford_item_keys(
    keymap: &mut HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
    item: FordItem,
    references: &[authorize_get_response::f1::chunk_references::ChunkReference],
    containers: &[ProtoContainer],
    network_policy: MMCSGetNetworkPolicy,
) -> Result<(), PushError> {
    if item.chunks.len() != references.len() {
        return Err(PushError::VerificationFailed);
    }

    for (ford, reference) in item.chunks.into_iter().zip(references) {
        fixed_bytes::<33>(&ford.key)?;
        let plaintext_length = fixed_bytes::<4>(&ford.chunk_len)?;
        if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
            && u64::from(u32::from_le_bytes(plaintext_length))
                > MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES
        {
            return Err(PushError::VerificationFailed);
        }
        let chunk = response_chunk(containers, reference.container_index, reference.chunk_index)?;
        let checksum = &chunk
            .meta
            .as_ref()
            .ok_or(PushError::VerificationFailed)?
            .checksum;
        fixed_bytes::<21>(checksum)?;
        let value = (ford.key, ford.chunk_len);
        if let Some(existing) = keymap.get(checksum) {
            if existing != &value {
                return Err(PushError::VerificationFailed);
            }
        } else {
            keymap.insert(checksum.clone(), value);
        }
    }
    Ok(())
}

async fn send_mmcs_req(
    client: &Client,
    config: &MMCSConfig,
    url: &str,
    method: &str,
    auth: &str,
    dsid: &str,
    body: &[u8],
) -> Result<Response, PushError> {
    let cloudkit_headers: HeaderMap = config
        .cloudkit_headers
        .iter()
        .map(|(a, b)| (HeaderName::from_str(a).unwrap(), b.parse().unwrap()))
        .collect();

    Ok(client
        .post(format!("{}/{}", url, method))
        .header("x-apple-mmcs-dataclass", config.dataclass)
        .header("x-apple-mmcs-auth", auth)
        .header("Accept", "application/vnd.com.apple.me.ubchunk+protobuf")
        .header(
            "x-apple-request-uuid",
            Uuid::new_v4().to_string().to_uppercase(),
        )
        .header("x-apple-mme-dsid", dsid)
        .header("x-mme-client-info", &config.mme_client_info)
        .header("Accept-Language", "en-us")
        .header(
            "Content-Type",
            "application/vnd.com.apple.me.ubchunk+protobuf",
        )
        .header("User-Agent", &config.user_agent)
        .header("x-apple-mmcs-proto-version", "5.0")
        .header("x-apple-mmcs-plist-version", "v1.0")
        .header("Accept-Encoding", "gzip, deflate")
        .header("Proxy-Connection", "keep-alive")
        .header("Connection", "keep-alive")
        .header(
            "x-apple-mmcs-plist-sha256",
            "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=",
        )
        .headers(cloudkit_headers)
        .body(body.to_owned())
        .send()
        .await?)
}

// build confirm request, mostly a bunch of analytics I don't care to track accurately
fn confirm_for_resp(
    resp: &Response,
    url: &str,
    conf_token: &str,
    up_md5: Option<&[u8]>,
) -> mmcsp::confirm_response::Request {
    let edge_info = resp
        .headers()
        .get("x-apple-edge-info")
        .clone()
        .map(|i| i.to_str().unwrap().to_string());
    let status = resp.status();
    let etag = resp
        .headers()
        .get("ETag")
        .clone()
        .map(|i| i.to_str().unwrap().to_string());
    mmcsp::confirm_response::Request {
        url: url.to_string(),
        status: status.as_u16() as u32,
        edge_info: [
            if up_md5.is_some() {
                vec![mmcsp::confirm_response::request::Metric {
                    n: "Etag".to_string(),
                    v: etag.unwrap(),
                }]
            } else {
                vec![]
            },
            if let Some(info) = edge_info {
                vec![mmcsp::confirm_response::request::Metric {
                    n: "x-apple-edge-info".to_string(),
                    v: info,
                }]
            } else {
                vec![]
            },
        ]
        .concat(),
        upload_md5: up_md5.map(|md5| md5.to_vec()),
        metrics: vec![],
        metrics2: vec![],
        token: conf_token.to_string(),
        f13: 0,
    }
}

// double sha256 because apple said so
fn gen_chunk_sig(chunk: &[u8], prefix: u8) -> ([u8; 21], [u8; 17]) {
    let out = sha256(chunk);

    let mut enc_key = [0u8; 17];
    enc_key[0] = 0x1;
    for i in 0..16 {
        enc_key[i + 1] = out[i] ^ out[i + 16];
    }

    (
        [vec![prefix], sha256(&out)[..20].to_vec()]
            .concat()
            .try_into()
            .unwrap(),
        enc_key,
    )
}

pub struct PreparedPut {
    pub total_sig: Vec<u8>,
    pub chunk_sigs: Vec<ChunkDesc>,
    pub total_len: usize,
    pub ford_key: Option<[u8; 32]>,
    pub ford: Option<([u8; 21], Vec<u8>)>,
}

pub async fn prepare_put(
    mut reader: impl ReadContainer + Send + Sync,
    encrypt: bool,
    prefix: u8,
) -> Result<PreparedPut, PushError> {
    let mut total_len = 0;
    let mut total_hasher = Sha1::new();
    total_hasher.update(b"com.apple.XattrObjectSalt\0com.apple.DataObjectSalt\0");
    let mut chunk_sigs: Vec<ChunkDesc> = vec![];

    let mut chunk = reader.read(5242880).await?;
    // chunk data into chunks of 5MB, generating a signature for each chunk
    while chunk.len() > 0 {
        total_hasher.update(&chunk);
        let (signature, key) = gen_chunk_sig(&chunk, prefix ^ 0x80);
        chunk_sigs.push(ChunkDesc {
            id: signature,
            size: chunk.len(),
            key: if encrypt {
                ChunkEncryption::V1(key)
            } else {
                ChunkEncryption::None
            },
            offset: None,
        });
        total_len += chunk.len();
        chunk = reader.read(5242880).await?;
    }
    Ok(PreparedPut {
        total_sig: [vec![prefix], total_hasher.finish().to_vec()].concat(),
        chunk_sigs,
        total_len,
        ford_key: None,
        ford: None,
    })
}

pub async fn prepare_put_v2(
    mut reader: impl ReadContainer + Send + Sync,
    boundary_key: &[u8],
) -> Result<PreparedPut, PushError> {
    let mut total_len = 0;
    let mut total_hasher = openssl::sha::Sha256::new();
    total_hasher.update(b"com.apple.DataObjectSaltV2");
    let mut chunk_sigs: Vec<ChunkDesc> = vec![];

    let mut ford_references = vec![];
    let mut chunk = reader.read(5242880).await?;
    // chunk data into chunks of 5MB, generating a signature for each chunk
    while chunk.len() > 0 {
        total_hasher.update(&chunk);

        let mut chunk_key: [u8; 33] = rand::random();
        chunk_key[0] = 0x04;

        let hk = Hkdf::<Sha256>::new(None, &chunk_key[1..]);
        let mut expanded_key = [0u8; 0x60];
        hk.expand("signature-key".as_bytes(), &mut expanded_key)
            .unwrap();

        let plaintext_hash = sha256(&chunk);
        let sig_hmac = PKey::hmac(&expanded_key[0x00..0x20])?;
        let mut h = Signer::new(MessageDigest::sha256(), &sig_hmac)?
            .sign_oneshot_to_vec(&plaintext_hash)?;
        h.insert(0, 0x84);
        h.resize(21, 0);

        ford_references.push(FordChunkItem {
            key: chunk_key.to_vec(),
            chunk_len: (chunk.len() as u32).to_le_bytes().to_vec(),
        });

        chunk_sigs.push(ChunkDesc {
            id: h.try_into().unwrap(),
            size: chunk.len(),
            key: ChunkEncryption::V2(chunk_key, (chunk.len() as u32).to_le_bytes()),
            offset: None,
        });
        total_len += chunk.len();
        chunk = reader.read(5242880).await?;
    }

    let hash = total_hasher.finish();

    let hk = Hkdf::<Sha256>::new(None, boundary_key);
    let mut file_key = [0u8; 0x20];
    hk.expand("file-key".as_bytes(), &mut file_key).unwrap();

    let hk = Hkdf::<Sha256>::new(None, &file_key);
    let mut checksum = [0u8; 0x20];
    hk.expand(&hash, &mut checksum).unwrap();

    let hmac = PKey::hmac(&checksum)?;
    let mut signature = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&hash)?;
    signature.insert(0, 0x04);
    signature.resize(21, 0);

    let total_ford = FordChunk {
        item: Some(FordItem {
            chunks: ford_references,
            checksum: checksum.to_vec(),
        }),
    };
    let ford_key: [u8; 32] = rand::random();

    let hk = Hkdf::<Sha256>::new(Some("PCSMMCS2".as_bytes()), &ford_key);
    let mut result = [0u8; 64];
    hk.expand(&[], &mut result).unwrap();

    let mut cipher = CmacSiv::<Aes256>::new_from_slice(&result).unwrap();
    let ford_iv: [u8; 16] = rand::random();
    // first byte is 4 if initial key is 256 bit, 3 otherwise
    let data = cipher
        .encrypt::<&[&[u8]], &&[u8]>(&[&ford_iv, &[0x04]], &total_ford.encode_to_vec())
        .unwrap();
    let encrypted_ford = [&[0x04][..], &ford_iv, &data].concat();

    let mut ford_signature = sha1(&ford_key).to_vec();
    ford_signature.insert(0, 0x01);

    Ok(PreparedPut {
        total_sig: signature,
        chunk_sigs,
        total_len,
        ford_key: Some(ford_key),
        ford: Some((ford_signature.try_into().unwrap(), encrypted_ford)),
    })
}

// a `Container` that transfers to an MMCS bucket
// handles putting into a bucket
struct MMCSPutContainer {
    target: UploadTarget,
    hasher: Hasher,
    sender: Option<flume::Sender<Result<Vec<u8>, PushError>>>,
    finalize: Option<JoinHandle<Result<Response, PushError>>>,
    length: usize,
    transfer_progress: usize,
    finish_binary: Option<Vec<u8>>,
    dsid: String,
    confirm_url: String,
    buffer: Option<Vec<u8>>,
    user_agent: String,
}

impl MMCSPutContainer {
    fn new(
        target: UploadTarget,
        length: usize,
        finish_binary: Option<Vec<u8>>,
        dsid: String,
        confirm_url: String,
        user_agent: String,
    ) -> MMCSPutContainer {
        MMCSPutContainer {
            target,
            hasher: Hasher::new(MessageDigest::md5()).unwrap(),
            sender: None,
            finalize: None,
            length,
            transfer_progress: 0,
            finish_binary,
            dsid,
            confirm_url,
            buffer: None,
            user_agent,
        }
    }

    fn get_chunks(&self, index: &HashMap<String, ChunkDesc>) -> Vec<ChunkDesc> {
        self.target
            .chunks
            .iter()
            .map(|chunk| index[&encode_hex(&chunk_id_to_id(chunk))].clone())
            .collect()
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) {
        if self.sender.is_none() {
            let (sender, receiver) = flume::bounded(0);
            self.sender = Some(sender);
            let body: Body = Body::wrap_stream(receiver.into_stream());
            let request = self.target.request.clone().unwrap();
            let user_agent = self.user_agent.clone();
            let task = tokio::spawn(async move {
                let response =
                    transfer_mmcs_container(&REQWEST, &request, Some(body), &user_agent).await?;
                Ok::<_, PushError>(response)
            });
            self.finalize = Some(task);
        }
    }
}

impl Container for MMCSPutContainer {}

#[async_trait]
impl WriteContainer for MMCSPutContainer {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        self.ensure_stream().await;

        if let Some(data) = self.buffer.take() {
            if let Err(err) = self.sender.as_ref().unwrap().send_async(Ok(data)).await {
                err.into_inner()?;
            }
        }
        self.buffer = Some(data.to_vec());
        self.hasher.update(data).unwrap();
        self.transfer_progress += data.len();
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    // finalize the http stream
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        let result = self.hasher.finish()?;

        return Ok(
            if complete_req_at_edge(self.target.request.as_ref().unwrap()) {
                debug!("MMCS complete at edge");
                let footer = mmcsp::PutFooter {
                    md5_sum: result.to_vec(),
                    confirm_data: self.finish_binary.clone(),
                };

                let mut buf: Vec<u8> = footer.encode_to_vec();

                let result = self
                    .sender
                    .take()
                    .unwrap()
                    .into_send_async(Ok([
                        self.buffer.take().unwrap(),
                        (buf.len() as u32).to_be_bytes().to_vec(),
                        buf,
                    ]
                    .concat()))
                    .await;
                if let Err(err) = result {
                    err.into_inner()?;
                }
                let reader = self.finalize.take().unwrap().await.unwrap()?;

                if !reader.status().is_success() {
                    let status = reader.status().as_u16();
                    debug!(
                        "mmcs failed {status} {}",
                        encode_hex(&reader.bytes().await?)
                    );
                    return Err(PushError::MMCSUploadFailed(status));
                }

                debug!("mmcs response {}", encode_hex(&reader.bytes().await?));

                None
            } else {
                debug!("MMCS complete normal");
                if let Err(err) = self
                    .sender
                    .as_ref()
                    .unwrap()
                    .send_async(Ok(self.buffer.take().unwrap()))
                    .await
                {
                    err.into_inner()?;
                }
                self.sender = None;
                let reader = self.finalize.take().unwrap().await.unwrap()?;
                let confirmed = confirm_for_resp(
                    &reader,
                    &get_container_url(&self.target.request.as_ref().unwrap()),
                    &self.target.cl_auth_p2,
                    Some(&result),
                );
                reader.bytes().await?;

                let confirmation = mmcsp::ConfirmResponse {
                    inner: vec![confirmed],
                    confirm_data: self.finish_binary.clone(),
                };
                let buf: Vec<u8> = confirmation.encode_to_vec();
                let resp = send_mmcs_req(
                    &REQWEST,
                    config,
                    &self.confirm_url,
                    "putComplete",
                    &format!(
                        "{} {} {}",
                        self.target.cl_auth_p1, self.length, self.target.cl_auth_p2
                    ),
                    &self.dsid,
                    &buf,
                )
                .await?;
                if !resp.status().is_success() {
                    return Err(PushError::MMCSUploadFailed(resp.status().as_u16()));
                }

                let body: Vec<u8> = resp.bytes().await?.into();

                debug!("Received MMCS put-complete response (bytes={})", body.len());

                let response = mmcsp::PutCompleteResponse::decode(&mut Cursor::new(&body))
                    .expect("Put complete decode fail");

                Some(MMCSReceipt::Put(response))
            },
        );
    }
}

enum SplitContainer<T> {
    Data(T),
    Ford(FileContainer<Cursor<Vec<u8>>>),
}

#[async_trait]
impl<T: Send + Sync> Container for SplitContainer<T> {}

#[async_trait]
impl<T: ReadContainer + Send + Sync> ReadContainer for SplitContainer<T> {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        match self {
            Self::Data(t) => t.read(len).await,
            Self::Ford(cont) => cont.read(len).await,
        }
    }
}

pub struct FileContainer<T> {
    inner: T,
    cacher: DataCacher,
}

impl<T> FileContainer<T> {
    pub fn new<'a>(inner: T) -> Self {
        Self {
            inner,
            cacher: DataCacher::new(),
        }
    }
}

#[async_trait]
impl<T: Send + Sync> Container for FileContainer<T> {}

#[async_trait]
impl<T: Read + Send + Sync> ReadContainer for FileContainer<T> {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let mut data = vec![0; len];
            let read = self.inner.read(&mut data)?;
            if read == 0 {
                recieved = self
                    .cacher
                    .read_exact(len)
                    .or_else(|| Some(self.cacher.read_all()));
                break;
            } else {
                data.resize(read, 0);
                self.cacher.data_avail(&data);
            }
            recieved = self.cacher.read_exact(len);
        }

        Ok(recieved.unwrap_or(vec![]))
    }
}

#[async_trait]
impl<T: Write + Send + Sync> WriteContainer for FileContainer<T> {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        self.inner.write_all(data)?;
        Ok(())
    }
}

pub async fn authorize_put(
    config: &MMCSConfig,
    inputs: &[(
        &PreparedPut,
        Option<String>,
        impl ReadContainer + Send + Sync,
    )],
    url: &str,
) -> Result<AuthorizedOperation, PushError> {
    let (_, buf) = put_authorize_body(config, inputs);
    let request = send_mmcs_req(
        &REQWEST,
        config,
        url,
        "authorizePut",
        &format!(
            "{} {} {}",
            encode_hex(&inputs[0].0.total_sig),
            inputs[0].0.total_len,
            inputs[0].1.clone().unwrap()
        ),
        config.dsid.as_ref().unwrap(),
        &buf,
    )
    .await?;
    let body = request.bytes().await?;

    Ok(AuthorizedOperation {
        url: url.to_string(),
        body: body.into(),
        dsid: config.dsid.clone().unwrap(),
    })
}

pub fn get_headers(mme_client_info: String) -> HashMap<&'static str, String> {
    [
        ("x-apple-mmcs-proto-version", "5.0".to_string()),
        (
            "x-apple-mmcs-plist-sha256",
            "fvj0Y/Ybu1pq0r4NxXw3eP51exujUkEAd7LllbkTdK8=".to_string(),
        ),
        ("x-apple-mmcs-plist-version", "v1.0".to_string()),
        ("x-mme-client-info", mme_client_info),
    ]
    .into_iter()
    .collect()
}

pub fn put_authorize_body(
    config: &MMCSConfig,
    inputs: &[(
        &PreparedPut,
        Option<String>,
        impl ReadContainer + Send + Sync,
    )],
) -> (HashMap<&'static str, String>, Vec<u8>) {
    let get = mmcsp::AuthorizePut {
        data: inputs
            .iter()
            .map(|(prepared, object, _)| mmcsp::authorize_put::PutData {
                sig: prepared.total_sig.clone(),
                token: Some(object.clone().unwrap_or_default()), // TODO changed; verify doesn't break other stuff
                chunks: prepared
                    .chunk_sigs
                    .iter()
                    .map(|chunk| mmcsp::authorize_put::put_data::Chunk {
                        sig: chunk.id.to_vec(),
                        size: chunk.size as u32,
                        encryption_key: if let ChunkEncryption::V1(e) = chunk.key {
                            Some(e.to_vec())
                        } else {
                            None
                        },
                    })
                    .collect(),
                ford_sig: prepared.ford.as_ref().map(|c| c.0.to_vec()),
                ford_desc: prepared.ford.as_ref().map(|c| FordDesc {
                    len: c.1.len() as u32,
                }),
                footer: Some(mmcsp::authorize_put::put_data::Footer {
                    chunk_count: prepared.chunk_sigs.len() as u32,
                    profile_type: "kCKProfileTypeFixed".to_string(),
                    f103: Some(0),
                    f102: config.extra_1.clone(),
                    f104: config.extra_2.clone(),
                }),
            })
            .collect(),
        f3: 81,
    };
    let buf: Vec<u8> = get.encode_to_vec();

    (get_headers(config.mme_client_info.to_string()), buf)
}

#[derive(Default, Clone)]
pub struct AuthorizedOperation {
    pub url: String,
    pub body: Vec<u8>,
    pub dsid: String,
}

fn ford_idx_to_id(idx: u32) -> [u8; 21] {
    let mut data = vec![0x7f];
    data.extend(idx.to_le_bytes());
    data.resize(21, 0);
    data.try_into().unwrap()
}

fn chunk_id_to_id(id: &ChunkIdentifier) -> [u8; 21] {
    if let Some(chunk_id) = &id.chunk_id {
        chunk_id.clone().try_into().unwrap()
    } else if let Some(ford_idx) = &id.ford_index {
        ford_idx_to_id(*ford_idx)
    } else {
        panic!("no chunk id")
    }
}

// upload data to mmcs
pub async fn put_mmcs(
    config: &MMCSConfig,
    inputs: Vec<(
        &PreparedPut,
        Option<String>,
        impl ReadContainer + Send + Sync,
    )>,
    auth: AuthorizedOperation,
    progress: impl FnMut(usize, usize) + Send + Sync,
) -> Result<(String, Option<String>, HashMap<Vec<u8>, String>), PushError> {
    let mut inputs = inputs
        .into_iter()
        .map(|(a, b, c)| (a, b, Some(c)))
        .collect::<Vec<_>>();

    let AuthorizedOperation { url, body, dsid } = auth;

    let mut receipts: HashMap<Vec<u8>, String> = HashMap::new();

    let response = mmcsp::AuthorizePutResponse::decode(&mut Cursor::new(body)).unwrap();

    let mut sources = inputs
        .iter_mut()
        .map(|(prepared, _, container)| {
            ChunkedContainer::new(
                prepared
                    .chunk_sigs
                    .clone()
                    .into_iter()
                    .map(|mut i| {
                        // This is the locally prepared plaintext source. The
                        // corresponding upload target applies and verifies the
                        // protocol encryption/signature before network I/O.
                        i.key = ChunkEncryption::TrustedLocal;
                        i
                    })
                    .collect(),
                SplitContainer::Data(container.take().expect("Duplicate PUT containers??")),
            )
        })
        .collect::<Vec<_>>();

    let mut index: HashMap<String, ChunkDesc> = inputs
        .iter()
        .flat_map(|s| s.0.chunk_sigs.iter().map(|c| (encode_hex(&c.id), *c)))
        .collect::<HashMap<_, _>>();

    let mut ford_ctr = 0;
    for state in &response.current_states {
        if let Some(ford_id) = &state.ford_id {
            let ford_data = inputs
                .iter()
                .find_map(|f| {
                    if let Some(ford) = &f.0.ford {
                        if &ford.0[..] == &ford_id[..] {
                            return Some(ford.1.clone());
                        }
                    }
                    None
                })
                .unwrap();

            let desc = ChunkDesc {
                id: ford_idx_to_id(ford_ctr),
                size: ford_data.len(),
                // Upload-only FORD indices are routing identifiers, not MMCS
                // content checksums. The FORD payload authenticates itself.
                key: ChunkEncryption::TrustedLocal,
                offset: None,
            };

            index.insert(encode_hex(&ford_idx_to_id(ford_ctr)), desc.clone());

            sources.push(ChunkedContainer::new(
                vec![desc],
                SplitContainer::Ford(FileContainer::new(Cursor::new(ford_data))),
            ));
            ford_ctr += 1;
        }

        let Some(receipt) = &state.receipt else {
            continue;
        };
        receipts.insert(state.signature.clone(), receipt.clone());
    }

    let targets: Vec<ChunkedContainer<MMCSPutContainer>> = response
        .targets
        .iter()
        .map(|target| {
            let len = target.chunks.iter().fold(0, |acc, chunk| {
                let wanted_chunk = index[&encode_hex(&chunk_id_to_id(chunk))];
                wanted_chunk.size + acc
            });
            let target = MMCSPutContainer::new(
                target.clone(),
                len,
                response.confirm_data.clone(),
                dsid.clone(),
                url.clone(),
                config.user_agent.clone(),
            );
            ChunkedContainer::new(target.get_chunks(&index), target)
        })
        .collect();

    // and, hopefully, everything "just works."
    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: inputs.iter().fold(0, |acc, chunk| chunk.0.total_len + acc),
    };
    matcher.transfer_chunks(config, progress).await?;

    receipts.extend(matcher.get_confirm_reciepts().iter().flat_map(|i| {
        let MMCSReceipt::Put(g) = i else {
            panic!("Bad receipt type")
        };
        g.finished
            .iter()
            .map(|i| (i.signature.clone(), i.receipt.clone()))
    }));

    Ok((url, inputs[0].1.clone(), receipts))
}

fn get_container_url(req: &HttpRequest) -> String {
    format!("{}://{}:{}{}", req.scheme, req.domain, req.port, req.path)
}

fn complete_req_at_edge(req: &HttpRequest) -> bool {
    req.headers.iter().find_map(|header| {
        if header.name == "x-apple-put-complete-at-edge-version" {
            Some(header.value.as_str())
        } else {
            None
        }
    }) == Some("2")
}

pub async fn transfer_mmcs_container(
    client: &Client,
    req: &HttpRequest,
    body: Option<Body>,
    user_agent: &str,
) -> Result<Response, PushError> {
    let data_url = get_container_url(req);
    let mut upload_resp = match req.method.as_str() {
        "GET" => client.get(&data_url),
        "PUT" => client.put(&data_url),
        _ => return Err(PushError::VerificationFailed),
    }
    .header(
        "x-apple-request-uuid",
        Uuid::new_v4().to_string().to_uppercase(),
    )
    .header("user-agent", user_agent);
    let completing_at_edge = complete_req_at_edge(req);
    for header in &req.headers {
        if (header.name == "Content-Length" && completing_at_edge) || header.name == "Host" {
            continue; // this isn't a rustpush hack, this is how you *think different*
        }
        upload_resp = upload_resp.header(header.name.clone(), header.value.clone());
    }

    if let Some(body) = body {
        upload_resp = upload_resp.body(body);
    }

    Ok(upload_resp.send().await?)
}

async fn transfer_mmcs_download_only_container(
    request: &HttpRequest,
    user_agent: &str,
) -> Result<Response, PushError> {
    validate_download_only_chunk_request(request)?;
    let client = build_pinned_download_only_client(&request.domain).await?;

    let mut headers = HeaderMap::new();
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("host") {
            continue;
        }
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| PushError::VerificationFailed)?;
        let value =
            HeaderValue::from_str(&header.value).map_err(|_| PushError::VerificationFailed)?;
        headers.append(name, value);
    }

    Ok(client
        .get(get_container_url(request))
        .header(
            "x-apple-request-uuid",
            Uuid::new_v4().to_string().to_uppercase(),
        )
        .header("user-agent", user_agent)
        .headers(headers)
        .send()
        .await?)
}

#[async_trait]
pub trait Container {}

#[async_trait]
pub trait ReadContainer: Container {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError>;
    async fn skip(&mut self, mut len: usize) -> Result<(), PushError> {
        while len > 0 {
            let step = len.min(MMCS_BOUNDED_SKIP_BYTES);
            if self.read(step).await?.len() != step {
                return Err(PushError::VerificationFailed);
            }
            len -= step;
        }
        Ok(())
    }
    // read ONE chunk
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        Ok(None)
    }
    // this should represent the byte count that represents transfer *progress*
    // if this is a file container, return 0 as writing to disk does not indicate progress
    fn get_progress_count(&self) -> usize {
        0
    }
}

#[async_trait]
pub trait WriteContainer: Container {
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError>;
    // read ONE chunk
    async fn finalize(&mut self, config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        Ok(None)
    }
    // this should represent the byte count that represents transfer *progress*
    // if this is a file container, return 0 as writing to disk does not indicate progress
    fn get_progress_count(&self) -> usize {
        0
    }
}

#[derive(Clone, Copy)]
pub struct ChunkDesc {
    id: [u8; 21],
    size: usize,
    key: ChunkEncryption,
    offset: Option<usize>,
}

impl ChunkDesc {
    fn verify_legacy_integrity(&self, data: &[u8]) -> Result<(), PushError> {
        let (signature, _) = gen_chunk_sig(data, self.id[0]);
        if signature != self.id {
            return Err(PushError::VerificationFailed);
        }
        Ok(())
    }

    fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, PushError> {
        Ok(match self.key {
            ChunkEncryption::V1(key) => {
                self.verify_legacy_integrity(&data)?;
                encrypt(Cipher::aes_128_cfb128(), &key[1..], None, &data)?
            }
            ChunkEncryption::V2(key, _) => {
                let hk = Hkdf::<Sha256>::new(None, &key[1..]);
                let mut expanded_key = [0u8; 0x60];
                hk.expand("signature-key".as_bytes(), &mut expanded_key)
                    .map_err(|_| PushError::VerificationFailed)?;

                let hmac = PKey::hmac(&expanded_key[0x20..0x40])?;

                let mut id = self.id[1..].to_vec();
                id.resize(40, 0);
                id[32..36].copy_from_slice(
                    &u32::try_from(data.len())
                        .map_err(|_| PushError::VerificationFailed)?
                        .to_le_bytes(),
                );

                let h = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&id)?;

                let plaintext_hash = sha256(&data);

                let result = encrypt(
                    Cipher::aes_256_ctr(),
                    &&expanded_key[0x40..0x60],
                    Some(&h[..16]),
                    &data,
                )?;

                let sig_hmac = PKey::hmac(&expanded_key[0x00..0x20])?;
                let h = Signer::new(MessageDigest::sha256(), &sig_hmac)?
                    .sign_oneshot_to_vec(&plaintext_hash)?;

                if &h[..self.id.len() - 1] != &self.id[1..] {
                    return Err(PushError::VerificationFailed);
                }

                result
            }
            ChunkEncryption::None => {
                self.verify_legacy_integrity(&data)?;
                data
            }
            ChunkEncryption::TrustedLocal
            | ChunkEncryption::VerifiedRemotePlaintext
            | ChunkEncryption::FordEnvelope => data,
        })
    }

    fn decrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, PushError> {
        Ok(match self.key {
            ChunkEncryption::V1(key) => {
                let result = decrypt(Cipher::aes_128_cfb128(), &key[1..], None, &data)?;
                self.verify_legacy_integrity(&result)?;
                result
            }
            ChunkEncryption::V2(key, len) => {
                let hk = Hkdf::<Sha256>::new(None, &key[1..]);
                let mut expanded_key = [0u8; 0x60];
                hk.expand("signature-key".as_bytes(), &mut expanded_key)
                    .map_err(|_| PushError::VerificationFailed)?;

                let hmac = PKey::hmac(&expanded_key[0x20..0x40])?;

                let mut id = self.id[1..].to_vec();
                id.resize(40, 0);
                id[32..36].copy_from_slice(
                    &u32::try_from(data.len())
                        .map_err(|_| PushError::VerificationFailed)?
                        .to_le_bytes(),
                );

                let h = Signer::new(MessageDigest::sha256(), &hmac)?.sign_oneshot_to_vec(&id)?;

                let mut result = decrypt(
                    Cipher::aes_256_ctr(),
                    &&expanded_key[0x40..0x60],
                    Some(&h[..16]),
                    &data,
                )?;
                // padded with zeros sometimes
                let length = u32::from_le_bytes(len) as usize;
                result.resize(length, 0);

                let plaintext_hash = sha256(&result);

                let sig_hmac = PKey::hmac(&expanded_key[0x00..0x20])?;
                let h = Signer::new(MessageDigest::sha256(), &sig_hmac)?
                    .sign_oneshot_to_vec(&plaintext_hash)?;

                if &h[..self.id.len() - 1] != &self.id[1..] {
                    return Err(PushError::VerificationFailed);
                }

                result
            }
            ChunkEncryption::None => {
                self.verify_legacy_integrity(&data)?;
                data
            }
            ChunkEncryption::TrustedLocal | ChunkEncryption::FordEnvelope => data,
            // This mode is destination-only. A network source must authenticate
            // its own V1, V2, or legacy checksum before the matcher exposes
            // plaintext to a file target.
            ChunkEncryption::VerifiedRemotePlaintext => return Err(PushError::VerificationFailed),
        })
    }
}

#[derive(Clone, Copy)]
pub enum ChunkEncryption {
    V1([u8; 17]),
    V2([u8; 33], [u8; 4]),
    None,
    /// Locally prepared upload plaintext whose target performs the protocol
    /// integrity check before network I/O.
    TrustedLocal,
    /// Download plaintext already authenticated by the matching remote source.
    /// File targets must not reinterpret a Ford V2 HMAC identifier as a legacy
    /// double-SHA identifier and verify it a second time.
    VerifiedRemotePlaintext,
    /// Encrypted FORD metadata. Its requested key-derived reference is fenced
    /// before transfer and its ciphertext is authenticated by AES-SIV before
    /// any contained chunk keys are used.
    FordEnvelope,
}

// used for files on disk and containers, for files there is just one container with the chunks in "correct order"
struct ChunkedContainer<T: Container> {
    chunks: Vec<ChunkDesc>,
    // either reading or writing
    current_chunk: usize,
    current_offset: usize,
    // only used when writing
    cached_chunks: HashMap<[u8; 21], Vec<u8>>,
    container: T,
}

impl<T: Container + Send + Sync> ChunkedContainer<T> {
    fn new(chunks: Vec<ChunkDesc>, container: T) -> Self {
        Self {
            chunks,
            current_chunk: 0,
            current_offset: 0,
            cached_chunks: HashMap::new(),
            container,
        }
    }

    fn complete(&self) -> bool {
        self.current_chunk == self.chunks.len()
    }

    fn wanted_chunk(&self) -> Option<[u8; 21]> {
        self.chunks.get(self.current_chunk).map(|c| c.id)
    }
}

impl<T: ReadContainer + Send + Sync> ChunkedContainer<T> {
    // (chunk id, data)
    async fn read_next(&mut self) -> Result<([u8; 21], Vec<u8>), PushError> {
        let reading_chunk = *self
            .chunks
            .get(self.current_chunk)
            .ok_or(PushError::VerificationFailed)?;
        self.current_chunk += 1;

        // skip over FORD chunks
        if let Some(offset) = reading_chunk.offset {
            if offset != self.current_offset {
                let seek_offset = offset
                    .checked_sub(self.current_offset)
                    .ok_or(PushError::VerificationFailed)?;
                warn!("Seeking {} bytes!", seek_offset);
                self.container.skip(seek_offset).await?;
                self.current_offset = self
                    .current_offset
                    .checked_add(seek_offset)
                    .ok_or(PushError::VerificationFailed)?;
            }
        }

        let data = self.container.read(reading_chunk.size).await?;
        if data.len() != reading_chunk.size {
            return Err(PushError::VerificationFailed);
        }
        self.current_offset = self
            .current_offset
            .checked_add(data.len())
            .ok_or(PushError::VerificationFailed)?;

        let data = reading_chunk.decrypt(data)?;

        Ok((reading_chunk.id, data))
    }
}

impl<T: WriteContainer + Send + Sync> ChunkedContainer<T> {
    async fn write_chunk(&mut self, chunk: &([u8; 21], Vec<u8>)) -> Result<(), PushError> {
        let chunk_id = chunk.0;
        let chunk_value = chunk.1.clone();
        let reading_chunk = *self
            .chunks
            .iter()
            .find(|c| &c.id[..] == &chunk.0)
            .ok_or(PushError::VerificationFailed)?;

        let chunk_value = reading_chunk.encrypt(chunk_value)?;

        // are we current chunk?
        if Some(chunk_id) == self.wanted_chunk() {
            // write right now (stream)
            self.container.write(&chunk_value).await?;
            self.current_chunk += 1;
            if !self.complete() {
                // try to catch up on any cached chunks
                while let Some(wanted) = self.wanted_chunk() {
                    let Some(cached) = self.cached_chunks.remove(&wanted) else {
                        break;
                    };
                    self.container.write(&cached).await?;
                    self.current_chunk += 1;

                    let wants_more = self.chunks[self.current_chunk..]
                        .iter()
                        .any(|c| c.id == wanted);
                    if wants_more {
                        warn!("Duplicate chunks!");
                        self.cached_chunks.insert(chunk_id, chunk_value.clone());
                    }
                }
            }
        }
        let wants_more = self.chunks[self.current_chunk..]
            .iter()
            .any(|c| c.id == chunk.0);
        if wants_more {
            warn!("Chunks out of order!");
            self.cached_chunks.insert(chunk_id, chunk_value.clone());
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum MMCSReceipt {
    Get(mmcsp::confirm_response::Request),
    Put(mmcsp::PutCompleteResponse),
}

// code that matches streams of chunks, and caches any extra chunks that are out of order
struct MMCSMatcher<A, B>
where
    A: ReadContainer,
    B: WriteContainer,
{
    sources: Vec<ChunkedContainer<A>>,
    targets: Vec<ChunkedContainer<B>>,
    reciepts: Vec<MMCSReceipt>,
    total: usize,
}

impl<A, B> MMCSMatcher<A, B>
where
    A: ReadContainer + Send + Sync,
    B: WriteContainer + Send + Sync,
{
    // find best source, first figuring out start chunks that align, or failing that whichever ones aren't complete
    fn best_source<'a>(
        targets: &Vec<ChunkedContainer<B>>,
        sources: &'a mut Vec<ChunkedContainer<A>>,
    ) -> Option<&'a mut ChunkedContainer<A>> {
        let wanted = sources
            .iter()
            .enumerate()
            .filter(|source| !source.1.complete())
            .filter_map(|(index, source)| {
                let first = source.chunks.first()?;
                let matches = targets
                    .iter()
                    .filter(|target| target.wanted_chunk() == Some(first.id))
                    .count();
                Some((index, matches))
            })
            .max_by_key(|(_, matches)| *matches);
        let wanted_idx = wanted.map(|(index, _)| index).unwrap_or(usize::MAX);
        // so now we know what we want, now we need to get a mutable reference
        sources.get_mut(wanted_idx)
    }

    async fn transfer_chunks(
        &mut self,
        config: &MMCSConfig,
        mut progress: impl FnMut(usize, usize) + Send + Sync,
    ) -> Result<(), PushError> {
        let mut total_source_progress = 0usize;
        while let Some(source) = Self::best_source(&self.targets, &mut self.sources) {
            while !source.complete() {
                let chunk = source.read_next().await?;
                // finialize if the source was just completed
                if source.complete() {
                    if let Some(data) = source.container.finalize(config).await? {
                        self.reciepts.push(data);
                    }
                }
                for target in &mut self.targets {
                    if !target.chunks.iter().any(|c| c.id == chunk.0) {
                        continue;
                    }
                    target.write_chunk(&chunk).await?;
                    // finialize if the target was just completed
                    if target.complete() {
                        if let Some(data) = target.container.finalize(config).await? {
                            self.reciepts.push(data);
                        }
                    }
                }
                let target_progress = self.targets.iter().try_fold(0usize, |acc, target| {
                    acc.checked_add(target.container.get_progress_count())
                        .ok_or(PushError::VerificationFailed)
                })?;
                let total_progress = total_source_progress
                    .checked_add(source.container.get_progress_count())
                    .and_then(|progress| progress.checked_add(target_progress))
                    .ok_or(PushError::VerificationFailed)?;
                info!(
                    "transferred attachment bytes {} of {}",
                    total_progress, self.total
                );
                progress(total_progress, self.total);
            }
            total_source_progress = total_source_progress
                .checked_add(source.container.get_progress_count())
                .ok_or(PushError::VerificationFailed)?;
        }
        Ok(())
    }

    fn get_confirm_reciepts(&self) -> &[MMCSReceipt] {
        &self.reciepts
    }
}

// simply caches data to be read in whole later
pub struct DataCacher {
    buf: Vec<u8>,
}

impl DataCacher {
    pub fn new() -> DataCacher {
        DataCacher { buf: vec![] }
    }

    pub fn data_avail(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn read_exact(&mut self, cnt: usize) -> Option<Vec<u8>> {
        return if self.buf.len() >= cnt {
            Some(self.buf.drain(..cnt).collect())
        } else {
            None
        };
    }

    pub fn read_all(&mut self) -> Vec<u8> {
        let buf = self.buf.clone();
        self.buf.clear();
        buf
    }
}

// a `Container` that transfers to an MMCS bucket
// simply allows reading exact amount of bytes from response
struct MMCSGetContainer {
    container: ProtoContainer,
    cacher: DataCacher,
    response: Option<Response>,
    confirm: Option<MMCSReceipt>,
    transfer_progress: usize,
    user_agent: String,
    network_policy: MMCSGetNetworkPolicy,
    response_byte_counter: Option<Arc<AtomicU64>>,
}

impl MMCSGetContainer {
    fn new(
        container: ProtoContainer,
        user_agent: String,
        network_policy: MMCSGetNetworkPolicy,
        response_byte_counter: Option<Arc<AtomicU64>>,
    ) -> Result<MMCSGetContainer, PushError> {
        if (network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly)
            != response_byte_counter.is_some()
        {
            return Err(PushError::VerificationFailed);
        }
        if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly {
            validate_download_only_chunk_request(
                container
                    .request
                    .as_ref()
                    .ok_or(PushError::VerificationFailed)?,
            )?;
        }
        Ok(MMCSGetContainer {
            container,
            cacher: DataCacher::new(),
            response: None,
            confirm: None,
            transfer_progress: 0,
            user_agent,
            network_policy,
            response_byte_counter,
        })
    }

    fn get_chunks(
        &self,
        keys: &HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)>,
        network_policy: MMCSGetNetworkPolicy,
        required_chunk_ids: &HashSet<[u8; 21]>,
    ) -> Result<Vec<ChunkDesc>, PushError> {
        let mut chunks = Vec::new();
        for chunk in &self.container.chunks {
            let Some(meta) = &chunk.meta else {
                continue;
            };
            let id = fixed_bytes::<21>(&meta.checksum)?;
            let size = usize::try_from(meta.size).map_err(|_| PushError::VerificationFailed)?;
            let offset = usize::try_from(meta.offset).map_err(|_| PushError::VerificationFailed)?;
            let key = if let Some((key, len)) = keys.get(&meta.checksum) {
                ChunkEncryption::V2(fixed_bytes::<33>(key)?, fixed_bytes::<4>(len)?)
            } else if let Some(key) = &meta.encryption_key {
                ChunkEncryption::V1(fixed_bytes::<17>(key)?)
            } else {
                ChunkEncryption::None
            };
            chunks.push(ChunkDesc {
                id,
                size,
                key,
                offset: Some(offset),
            });
        }
        Ok(select_source_chunks(
            chunks,
            network_policy,
            required_chunk_ids,
        ))
    }

    fn get_ford_chunks(
        &self,
        network_policy: MMCSGetNetworkPolicy,
        required_chunk_ids: &HashSet<[u8; 21]>,
    ) -> Result<Vec<ChunkDesc>, PushError> {
        let mut chunks = Vec::new();
        for chunk in &self.container.chunks {
            let Some(meta) = &chunk.encryption else {
                continue;
            };
            let for_chunks = meta
                .for_chunks
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            chunks.push(ChunkDesc {
                id: fixed_bytes::<21>(&for_chunks.keys_container)?,
                size: usize::try_from(meta.size).map_err(|_| PushError::VerificationFailed)?,
                // The requested FORD key is fenced to this reference and the
                // downloaded envelope is authenticated by AES-SIV on decode.
                key: ChunkEncryption::FordEnvelope,
                offset: Some(
                    usize::try_from(meta.offset).map_err(|_| PushError::VerificationFailed)?,
                ),
            });
        }
        Ok(select_source_chunks(
            chunks,
            network_policy,
            required_chunk_ids,
        ))
    }

    // opens an HTTP stream if not already open
    async fn ensure_stream(&mut self) -> Result<(), PushError> {
        if self.response.is_none() {
            let request = self
                .container
                .request
                .as_ref()
                .ok_or(PushError::VerificationFailed)?;
            if self.network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly {
                validate_download_only_chunk_request(request)?;
            }
            let response = if self.network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
            {
                transfer_mmcs_download_only_container(request, &self.user_agent).await?
            } else {
                transfer_mmcs_container(&REQWEST, request, None, &self.user_agent).await?
            };
            if self.network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
                && !response.status().is_success()
            {
                return Err(PushError::MMCSGetFailed(Some(format!(
                    "chunk GET returned HTTP {}",
                    response.status().as_u16()
                ))));
            }
            if self.network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
                && response
                    .content_length()
                    .is_some_and(|length| length > MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES)
            {
                return Err(PushError::VerificationFailed);
            }
            if self.network_policy.collects_completion_receipts() {
                self.confirm = Some(MMCSReceipt::Get(confirm_for_resp(
                    &response,
                    &get_container_url(request),
                    &self.container.cl_auth_p2,
                    None,
                )));
            }
            self.response = Some(response);
        }
        Ok(())
    }
}

#[async_trait]
impl Container for MMCSGetContainer {}

#[async_trait]
impl ReadContainer for MMCSGetContainer {
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        self.ensure_stream().await?;

        let mut received = self.cacher.read_exact(len);
        while received.is_none() {
            let response = self
                .response
                .as_mut()
                .ok_or(PushError::VerificationFailed)?;
            let Some(bytes) = response.chunk().await? else {
                return Ok(self.cacher.read_all());
            };
            if let Some(counter) = &self.response_byte_counter {
                record_preauthorized_response_bytes(counter, bytes.len())?;
            }
            self.cacher.data_avail(&bytes);
            received = self.cacher.read_exact(len);
        }

        let read = received.ok_or(PushError::VerificationFailed)?;
        self.transfer_progress = self
            .transfer_progress
            .checked_add(read.len())
            .ok_or(PushError::VerificationFailed)?;
        Ok(read)
    }

    fn get_progress_count(&self) -> usize {
        self.transfer_progress
    }

    async fn finalize(&mut self, _config: &MMCSConfig) -> Result<Option<MMCSReceipt>, PushError> {
        Ok(self.confirm.clone())
    }
}

pub async fn authorize_get(
    config: &MMCSConfig,
    url: &str,
    files: &[(
        Vec<u8>,
        &str,
        impl WriteContainer + Send + Sync,
        Option<Vec<u8>>,
    )],
) -> Result<AuthorizedOperation, PushError> {
    let confirmation = mmcsp::AuthorizeGet {
        item: files
            .iter()
            .map(|(sig, object, _, _)| mmcsp::authorize_get::Item {
                signature: sig.to_vec(),
                object: object.to_string(),
            })
            .collect(),
    };
    let buf: Vec<u8> = confirmation.encode_to_vec();
    let (sig, object, _, _) = &files[0];
    let request = send_mmcs_req(
        &REQWEST,
        config,
        &url,
        "authorizeGet",
        &format!("{} {}", encode_hex(&sig), object),
        config.dsid.as_ref().unwrap(),
        &buf,
    )
    .await?;

    Ok(AuthorizedOperation {
        url: url.to_string(),
        body: request.bytes().await?.into(),
        dsid: config.dsid.clone().unwrap(),
    })
}

async fn get_mmcs_with_network_policy(
    config: &MMCSConfig,
    authorized: AuthorizedOperation,
    files: Vec<(
        Vec<u8>,
        &str,
        impl WriteContainer + Send + Sync,
        Option<Vec<u8>>,
    )>,
    progress: impl FnMut(usize, usize) + Send + Sync,
    _ford: bool,
    network_policy: MMCSGetNetworkPolicy,
) -> Result<(), PushError> {
    let mut files = files
        .into_iter()
        .map(|(a, b, c, k)| (a, b, Some(c), k))
        .collect::<Vec<_>>();

    let AuthorizedOperation { url, body, dsid } = authorized;

    if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
        && (!url.is_empty() || !dsid.is_empty())
    {
        // A preauthorized CloudKit asset has no standalone authorizeGet or
        // getComplete endpoint. Rejecting either value prevents this path from
        // acquiring a mutation-capable completion destination.
        return Err(PushError::VerificationFailed);
    }
    if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly {
        validate_preauthorized_authorization_body(&body)?;
    }
    let response_byte_counter = (network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly)
        .then(|| Arc::new(AtomicU64::new(0)));

    debug!(
        "Received MMCS authorize-get response (bytes={})",
        body.len()
    );
    let response = mmcsp::AuthorizeGetResponse::decode(&mut Cursor::new(body))?;

    let Some(response_data) = response.f1.as_ref() else {
        let reason = response
            .error
            .as_ref()
            .and_then(|error| error.f2.as_ref())
            .map(|error| error.reason.clone());
        return Err(PushError::MMCSGetFailed(reason));
    };
    debug!(
        "Decoded MMCS authorize-get response (containers={}, references={})",
        response_data.containers.len(),
        response_data.references.len()
    );

    if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly {
        let requested_files = files
            .iter()
            .map(|(checksum, _, _, key)| (checksum.clone(), key.clone()))
            .collect::<Vec<_>>();
        let total_chunks = response_data
            .containers
            .iter()
            .map(|container| container.chunks.len())
            .sum::<usize>();
        let metadata_chunks = response_data
            .containers
            .iter()
            .flat_map(|container| &container.chunks)
            .filter(|chunk| chunk.meta.is_some())
            .count();
        let encrypted_chunks = response_data
            .containers
            .iter()
            .flat_map(|container| &container.chunks)
            .filter(|chunk| chunk.encryption.is_some())
            .count();
        let total_headers = response_data
            .containers
            .iter()
            .filter_map(|container| container.request.as_ref())
            .map(|request| request.headers.len())
            .sum::<usize>();
        let referenced_chunks = response_data
            .references
            .iter()
            .map(|reference| reference.chunk_references.len())
            .sum::<usize>();
        let ford_references = response_data
            .references
            .iter()
            .filter(|reference| reference.ford_reference.is_some())
            .count();
        let requested_keys = requested_files
            .iter()
            .filter(|(_, key)| key.is_some())
            .count();
        debug!(
            "Inspecting preauthorized MMCS shape (chunks={}, metadata_chunks={}, encrypted_chunks={}, headers={}, referenced_chunks={}, ford_references={}, requested_keys={})",
            total_chunks,
            metadata_chunks,
            encrypted_chunks,
            total_headers,
            referenced_chunks,
            ford_references,
            requested_keys
        );
        if let Err(error) =
            validate_preauthorized_download_response(response_data, &requested_files)
        {
            warn!("Rejected preauthorized MMCS response at decoded-response validation");
            return Err(error);
        }
        debug!(
            "Validated preauthorized MMCS response (requested_files={})",
            requested_files.len()
        );
    }

    let mut total_bytes = 0usize;
    for container in &response_data.containers {
        for chunk in &container.chunks {
            if let Some(meta) = &chunk.meta {
                let size = usize::try_from(meta.size).map_err(|_| PushError::VerificationFailed)?;
                total_bytes = total_bytes
                    .checked_add(size)
                    .ok_or(PushError::VerificationFailed)?;
            }
        }
    }

    let mut ford_containers = vec![];
    let containers = &response_data.containers;
    let mut targets = Vec::new();
    for wanted_chunks in &response_data.references {
        let Some(file_index) = files
            .iter()
            .position(|file| file.0 == wanted_chunks.file_checksum && file.2.is_some())
        else {
            continue;
        };

        if let Some(ford_reference) = &wanted_chunks.ford_reference {
            let ford_key = files
                .get(file_index)
                .and_then(|file| file.3.clone())
                .ok_or(PushError::VerificationFailed)?;
            ford_containers.push((
                wanted_chunks.chunk_references.clone(),
                ford_reference.clone(),
                Vec::new(),
                ford_key,
            ));
        }

        let mut target_chunks = Vec::with_capacity(wanted_chunks.chunk_references.len());
        for chunk_reference in &wanted_chunks.chunk_references {
            let chunk = response_chunk(
                containers,
                chunk_reference.container_index,
                chunk_reference.chunk_index,
            )?;
            let meta = chunk.meta.as_ref().ok_or(PushError::VerificationFailed)?;
            target_chunks.push(ChunkDesc {
                id: fixed_bytes::<21>(&meta.checksum)?,
                size: usize::try_from(meta.size).map_err(|_| PushError::VerificationFailed)?,
                // `MMCSGetContainer::read_next` authenticates each remote
                // source chunk according to its actual wire format before the
                // matcher exposes plaintext. The file target only orders and
                // writes those verified bytes. Reapplying the legacy checksum
                // here rejects valid Ford V2 HMAC identifiers.
                key: ChunkEncryption::VerifiedRemotePlaintext,
                offset: None,
            });
        }
        if target_chunks.is_empty() {
            return Err(PushError::VerificationFailed);
        }
        let writer = files
            .get_mut(file_index)
            .ok_or(PushError::VerificationFailed)?
            .2
            .take()
            .ok_or(PushError::VerificationFailed)?;
        targets.push(ChunkedContainer::new(target_chunks, writer));
    }
    debug!(
        "Prepared MMCS download targets (targets={}, ford_containers={})",
        targets.len(),
        ford_containers.len()
    );

    if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
        && (targets.len() != files.len() || files.iter().any(|file| file.2.is_some()))
    {
        return Err(PushError::VerificationFailed);
    }

    let mut ford_keymap: HashMap<Vec<u8>, (Vec<u8>, Vec<u8>)> = HashMap::new();
    if !ford_containers.is_empty() {
        {
            let mut ford_targets = Vec::with_capacity(ford_containers.len());
            for (_, ford_reference, ford_bytes, _) in &mut ford_containers {
                let chunk = response_chunk(
                    containers,
                    ford_reference.container_index,
                    ford_reference.chunk_index,
                )?;
                let encryption = chunk
                    .encryption
                    .as_ref()
                    .ok_or(PushError::VerificationFailed)?;
                let for_chunks = encryption
                    .for_chunks
                    .as_ref()
                    .ok_or(PushError::VerificationFailed)?;
                ford_targets.push(ChunkedContainer::new(
                    vec![ChunkDesc {
                        id: fixed_bytes::<21>(&for_chunks.keys_container)?,
                        size: usize::try_from(encryption.size)
                            .map_err(|_| PushError::VerificationFailed)?,
                        key: ChunkEncryption::FordEnvelope,
                        offset: None,
                    }],
                    FileContainer::new(Cursor::new(ford_bytes)),
                ));
            }

            let required_chunk_ids = ford_targets
                .iter()
                .flat_map(|target| target.chunks.iter().map(|chunk| chunk.id))
                .collect::<HashSet<_>>();
            let ford_sources: Vec<ChunkedContainer<MMCSGetContainer>> = containers
                .iter()
                .map(|container| {
                    let container = MMCSGetContainer::new(
                        container.clone(),
                        config.user_agent.clone(),
                        network_policy,
                        response_byte_counter.clone(),
                    )?;
                    let chunks = container.get_ford_chunks(network_policy, &required_chunk_ids)?;
                    Ok((!chunks.is_empty()).then(|| ChunkedContainer::new(chunks, container)))
                })
                .collect::<Result<Vec<_>, PushError>>()?
                .into_iter()
                .flatten()
                .collect();

            let mut matcher = MMCSMatcher {
                sources: ford_sources,
                targets: ford_targets,
                reciepts: vec![],
                total: total_bytes,
            };
            matcher.transfer_chunks(config, |_, _| {}).await?;
            if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
                && matcher.targets.iter().any(|target| !target.complete())
            {
                return Err(PushError::VerificationFailed);
            }
        }

        for (references, _ford_ref, ford, key) in ford_containers {
            let item = decode_ford_item(&ford, &key)?;
            add_ford_item_keys(
                &mut ford_keymap,
                item,
                &references,
                containers,
                network_policy,
            )?;
        }
    }

    let required_chunk_ids = targets
        .iter()
        .flat_map(|target| target.chunks.iter().map(|chunk| chunk.id))
        .collect::<HashSet<_>>();
    let sources: Vec<ChunkedContainer<MMCSGetContainer>> = containers
        .iter()
        .map(|container| {
            let container = MMCSGetContainer::new(
                container.clone(),
                config.user_agent.clone(),
                network_policy,
                response_byte_counter.clone(),
            )?;
            let chunks = container.get_chunks(&ford_keymap, network_policy, &required_chunk_ids)?;
            Ok((!chunks.is_empty()).then(|| ChunkedContainer::new(chunks, container)))
        })
        .collect::<Result<Vec<_>, PushError>>()?
        .into_iter()
        .flatten()
        .collect();
    debug!(
        "Prepared MMCS download sources (sources={}, required_chunks={})",
        sources.len(),
        required_chunk_ids.len()
    );

    let mut matcher = MMCSMatcher {
        sources,
        targets,
        reciepts: vec![],
        total: total_bytes,
    };
    matcher.transfer_chunks(config, progress).await?;
    debug!("Completed MMCS chunk transfer");
    if network_policy == MMCSGetNetworkPolicy::PreauthorizedDownloadOnly
        && matcher.targets.iter().any(|target| !target.complete())
    {
        return Err(PushError::VerificationFailed);
    }

    // cloudkit doesn't do getComplete
    if network_policy.sends_completion() && !url.is_empty() {
        let confirmations = matcher
            .get_confirm_reciepts()
            .iter()
            .map(|receipt| match receipt {
                MMCSReceipt::Get(receipt) => Ok(receipt.clone()),
                MMCSReceipt::Put(_) => Err(PushError::VerificationFailed),
            })
            .collect::<Result<Vec<_>, PushError>>()?;
        let confirmation = mmcsp::ConfirmResponse {
            inner: confirmations,
            confirm_data: None,
        };
        let buf: Vec<u8> = confirmation.encode_to_vec();
        let first_container = containers.first().ok_or(PushError::VerificationFailed)?;
        let resp = send_mmcs_req(
            &REQWEST,
            config,
            &url,
            "getComplete",
            &format!(
                "{} {}",
                first_container.cl_auth_p1, first_container.cl_auth_p2
            ),
            &dsid,
            &buf,
        )
        .await?;
        if !resp.status().is_success() {
            return Err(PushError::MMCSGetFailed(Some(format!(
                "getComplete returned HTTP {}",
                resp.status().as_u16()
            ))));
        }
    }

    Ok(())
}

pub async fn get_mmcs(
    config: &MMCSConfig,
    authorized: AuthorizedOperation,
    files: Vec<(
        Vec<u8>,
        &str,
        impl WriteContainer + Send + Sync,
        Option<Vec<u8>>,
    )>,
    progress: impl FnMut(usize, usize) + Send + Sync,
    ford: bool,
) -> Result<(), PushError> {
    get_mmcs_with_network_policy(
        config,
        authorized,
        files,
        progress,
        ford,
        MMCSGetNetworkPolicy::Standard,
    )
    .await
}

/// Downloads a CloudKit-provided MMCS authorization response using a closed
/// network shape: server-described HTTPS GETs only, no redirect following, no
/// application-level retry loop, no authorizeGet request, and no getComplete
/// acknowledgement. Chunk hashes, decryption, and whole-file integrity checks
/// remain in the normal matcher.
pub async fn get_mmcs_pre_authorized_download_only(
    config: &MMCSConfig,
    authorization_body: &[u8],
    files: Vec<(
        Vec<u8>,
        &str,
        impl WriteContainer + Send + Sync,
        Option<Vec<u8>>,
    )>,
    progress: impl FnMut(usize, usize) + Send + Sync,
) -> Result<(), PushError> {
    // Preflight before cloning so an oversized or malformed CloudKit body
    // cannot cause a second attacker-sized allocation before Prost sees it.
    debug!(
        "Validating preauthorized MMCS authorization body (bytes={})",
        authorization_body.len()
    );
    if let Err(error) = validate_preauthorized_authorization_body(authorization_body) {
        warn!("Rejected preauthorized MMCS response at authorization-body preflight");
        return Err(error);
    }
    debug!("Validated preauthorized MMCS authorization body");
    get_mmcs_with_network_policy(
        config,
        AuthorizedOperation {
            body: authorization_body.to_vec(),
            ..Default::default()
        },
        files,
        progress,
        false,
        MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
    )
    .await
}

#[cfg(test)]
mod download_only_tests {
    use super::*;
    use crate::mmcsp::{
        authorize_get_response::f1::{chunk_references::ChunkReference, ChunkReferences},
        container::{encryption_meta::EncryptedChunks, ChunkMeta, ChunkWrapper, EncryptionMeta},
        http_request::Header,
    };

    fn chunk_request(method: &str, scheme: &str) -> HttpRequest {
        HttpRequest {
            domain: "cvws.icloud-content.com".to_owned(),
            port: 443,
            method: method.to_owned(),
            path: "/mmcs/download/chunk".to_owned(),
            scheme: scheme.to_owned(),
            ..Default::default()
        }
    }

    fn chunk_reference(container_index: u32, chunk_index: u32) -> ChunkReference {
        ChunkReference {
            container_index,
            chunk_index,
        }
    }

    fn valid_download_response() -> (authorize_get_response::F1, Vec<(Vec<u8>, Option<Vec<u8>>)>) {
        let file_checksum = vec![0x11; 21];
        (
            authorize_get_response::F1 {
                containers: vec![ProtoContainer {
                    request: Some(chunk_request("GET", "https")),
                    chunks: vec![ChunkWrapper {
                        meta: Some(ChunkMeta {
                            checksum: vec![0x22; 21],
                            size: 16,
                            offset: 0,
                            ..Default::default()
                        }),
                        encryption: None,
                    }],
                    ..Default::default()
                }],
                references: vec![ChunkReferences {
                    file_checksum: file_checksum.clone(),
                    chunk_references: vec![chunk_reference(0, 0)],
                    ..Default::default()
                }],
            },
            vec![(file_checksum, None)],
        )
    }

    fn valid_ford_download_response(
    ) -> (authorize_get_response::F1, Vec<(Vec<u8>, Option<Vec<u8>>)>) {
        let (mut response, mut requested) = valid_download_response();
        let ford_key = vec![0x55; 32];
        response.containers[0].chunks.push(ChunkWrapper {
            meta: None,
            encryption: Some(EncryptionMeta {
                size: 32,
                offset: 16,
                for_chunks: Some(EncryptedChunks {
                    container: vec![0x33; 21],
                    keys_container: ford_key_signature(&ford_key).unwrap().to_vec(),
                }),
            }),
        });
        response.references[0].ford_reference = Some(chunk_reference(0, 1));
        requested[0].1 = Some(ford_key);
        (response, requested)
    }

    fn encode_test_varint(mut value: u64) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if value == 0 {
                return encoded;
            }
        }
    }

    fn append_test_message(output: &mut Vec<u8>, field_number: u32, payload: &[u8]) {
        output.extend(encode_test_varint((u64::from(field_number) << 3) | 2));
        output.extend(encode_test_varint(payload.len() as u64));
        output.extend_from_slice(payload);
    }

    fn wrap_test_message(field_number: u32, payload: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        append_test_message(&mut output, field_number, payload);
        output
    }

    fn repeated_empty_test_messages(field_number: u32, count: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(count.saturating_mul(2));
        for _ in 0..count {
            append_test_message(&mut output, field_number, &[]);
        }
        output
    }

    fn opaque_authorization_body(total_len: usize) -> Vec<u8> {
        for length_bytes in 1..=10usize {
            let Some(payload_len) = total_len.checked_sub(1 + length_bytes) else {
                continue;
            };
            let encoded_length = encode_test_varint(payload_len as u64);
            if encoded_length.len() == length_bytes {
                let mut body = Vec::with_capacity(total_len);
                body.push((15 << 3) | 2);
                body.extend(encoded_length);
                body.resize(total_len, 0);
                return body;
            }
        }
        panic!("unable to build exact-length protobuf test body");
    }

    fn assert_verification_failed<T>(result: Result<T, PushError>) {
        assert!(matches!(result, Err(PushError::VerificationFailed)));
    }

    #[test]
    fn download_only_policy_allows_only_exact_https_get_shape() {
        assert!(validate_download_only_chunk_request(&chunk_request("GET", "https")).is_ok());
        assert!(validate_download_only_chunk_request(&chunk_request("PUT", "https")).is_err());
        assert!(validate_download_only_chunk_request(&chunk_request("POST", "https")).is_err());
        assert!(validate_download_only_chunk_request(&chunk_request("GET", "http")).is_err());

        let mut authority_override = chunk_request("GET", "https");
        authority_override.headers.push(Header {
            name: "Host".to_owned(),
            value: "elsewhere.invalid".to_owned(),
        });
        assert!(validate_download_only_chunk_request(&authority_override).is_err());

        for value in ["cvws.icloud-content.com", "cvws.icloud-content.com:443"] {
            let mut redundant_authority = chunk_request("GET", "https");
            redundant_authority.headers.push(Header {
                name: "Host".to_owned(),
                value: value.to_owned(),
            });
            assert!(validate_download_only_chunk_request(&redundant_authority).is_ok());
        }

        let mut duplicate_authority = chunk_request("GET", "https");
        duplicate_authority.headers.extend([
            Header {
                name: "Host".to_owned(),
                value: "cvws.icloud-content.com".to_owned(),
            },
            Header {
                name: "host".to_owned(),
                value: "cvws.icloud-content.com".to_owned(),
            },
        ]);
        assert!(validate_download_only_chunk_request(&duplicate_authority).is_err());

        let mut method_override = chunk_request("GET", "https");
        method_override.headers.push(Header {
            name: "X-HTTP-Method-Override".to_owned(),
            value: "POST".to_owned(),
        });
        assert!(validate_download_only_chunk_request(&method_override).is_err());
    }

    #[test]
    fn download_only_policy_rejects_request_shape_headers_and_keeps_apple_auth() {
        for name in [
            "Host",
            "Connection",
            "Proxy-Connection",
            "Keep-Alive",
            "Transfer-Encoding",
            "TE",
            "Trailer",
            "Upgrade",
            "Content-Length",
            "Expect",
            "Forwarded",
            "Via",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Real-IP",
            "Authority",
            "X-Authority",
            "X-Host",
            "Destination",
            "X-HTTP-DestinationURL",
            "Max-Forwards",
            "Proxy",
            "Proxy-Authorization",
            "X-HTTP-Method",
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-Original-Method",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Envoy-Original-Path",
            "X-Amzn-Remapped-Host",
            "x-apple-put-complete-at-edge-version",
        ] {
            let mut request = chunk_request("GET", "https");
            request.headers.push(Header {
                name: name.to_owned(),
                value: "attacker-controlled".to_owned(),
            });
            assert_verification_failed(validate_download_only_chunk_request(&request));
        }

        for name in [
            "x-apple-mmcs-auth",
            "x-apple-mmcs-proto-version",
            "Authorization",
        ] {
            let mut request = chunk_request("GET", "https");
            request.headers.push(Header {
                name: name.to_owned(),
                value: "required-authorization".to_owned(),
            });
            assert!(validate_download_only_chunk_request(&request).is_ok());
        }
    }

    #[test]
    fn download_only_policy_requires_public_shaped_ascii_dns_on_port_443() {
        let mut request = chunk_request("GET", "https");
        request.port = 80;
        assert_verification_failed(validate_download_only_chunk_request(&request));

        for domain in [
            "localhost",
            "printer.local",
            "127.0.0.1",
            "cache..example.com",
            "-cache.example.com",
            "cache-.example.com",
            "cache.example.123",
            "caché.example.com",
        ] {
            let mut request = chunk_request("GET", "https");
            request.domain = domain.to_owned();
            assert_verification_failed(validate_download_only_chunk_request(&request));
        }

        let mut valid_hyphenated = chunk_request("GET", "https");
        valid_hyphenated.domain = "edge-cache.example.com".to_owned();
        assert!(validate_download_only_chunk_request(&valid_hyphenated).is_ok());

        let mut oversized_domain = chunk_request("GET", "https");
        oversized_domain.domain = format!("{}.example.com", "a.".repeat(122));
        assert_verification_failed(validate_download_only_chunk_request(&oversized_domain));
    }

    #[test]
    fn download_only_resolution_rejects_every_non_public_or_mixed_destination() {
        let socket = |address: &str| address.parse::<SocketAddr>().unwrap();
        for address in [
            "0.0.0.0:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "192.0.2.1:443",
            "198.18.0.1:443",
            "198.51.100.1:443",
            "203.0.113.1:443",
            "224.0.0.1:443",
            "[::]:443",
            "[::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[2001:2::1]:443",
            "[2001:db8::1]:443",
            "[3fff::1]:443",
            "[64:ff9b::7f00:1]:443",
            "[64:ff9b::c000:201]:443",
            "[ff02::1]:443",
        ] {
            assert_verification_failed(validate_download_only_resolved_addresses(&[socket(
                address,
            )]));
        }

        assert_verification_failed(validate_download_only_resolved_addresses(&[]));
        assert_verification_failed(validate_download_only_resolved_addresses(&[
            socket("8.8.8.8:443"),
            socket("127.0.0.1:443"),
        ]));
        assert_verification_failed(validate_download_only_resolved_addresses(&[socket(
            "8.8.8.8:80",
        )]));
        assert!(validate_download_only_resolved_addresses(&[
            socket("8.8.8.8:443"),
            socket("[2606:4700:4700::1111]:443"),
            socket("[64:ff9b::808:808]:443"),
        ])
        .is_ok());
    }

    #[test]
    fn download_only_policy_rejects_malformed_transport_headers_before_io() {
        let mut invalid_name = chunk_request("GET", "https");
        invalid_name.headers.push(Header {
            name: "bad header".to_owned(),
            value: "value".to_owned(),
        });
        assert_verification_failed(validate_download_only_chunk_request(&invalid_name));

        let mut invalid_value = chunk_request("GET", "https");
        invalid_value.headers.push(Header {
            name: "x-mmcs-test".to_owned(),
            value: "value\r\ninjected: true".to_owned(),
        });
        assert_verification_failed(validate_download_only_chunk_request(&invalid_value));
    }

    #[test]
    fn download_only_policy_cannot_collect_or_send_completion() {
        let policy = MMCSGetNetworkPolicy::PreauthorizedDownloadOnly;
        assert!(!policy.collects_completion_receipts());
        assert!(!policy.sends_completion());
        assert!(MMCSGetNetworkPolicy::Standard.collects_completion_receipts());
        assert!(MMCSGetNetworkPolicy::Standard.sends_completion());
    }

    #[test]
    fn download_only_container_rejects_mutating_server_request_before_io() {
        let container = ProtoContainer {
            request: Some(chunk_request("PUT", "https")),
            ..Default::default()
        };
        assert!(MMCSGetContainer::new(
            container,
            "test-agent".to_owned(),
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
            Some(Arc::new(AtomicU64::new(0))),
        )
        .is_err());
    }

    #[test]
    fn download_only_sources_are_reduced_to_requested_chunk_ids() {
        let chunk = |id| ChunkDesc {
            id: [id; 21],
            size: 1,
            key: ChunkEncryption::None,
            offset: None,
        };
        let required = HashSet::from([[2; 21]]);

        let selected = select_source_chunks(
            vec![chunk(1), chunk(2), chunk(3)],
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
            &required,
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, [2; 21]);

        let standard = select_source_chunks(
            vec![chunk(1), chunk(2), chunk(3)],
            MMCSGetNetworkPolicy::Standard,
            &required,
        );
        assert_eq!(standard.len(), 3);
    }

    #[test]
    fn malformed_response_indices_return_errors_instead_of_panicking() {
        let (response, requested) = valid_download_response();

        let mut bad_container = response.clone();
        bad_container.references[0].chunk_references[0].container_index = 1;
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_container,
            &requested,
        ));

        let mut bad_chunk = response;
        bad_chunk.references[0].chunk_references[0].chunk_index = 1;
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_chunk, &requested,
        ));
    }

    #[test]
    fn malformed_response_missing_metadata_or_ford_key_returns_errors() {
        let (mut missing_meta, requested) = valid_download_response();
        missing_meta.containers[0].chunks[0].meta = None;
        assert_verification_failed(validate_preauthorized_download_response(
            &missing_meta,
            &requested,
        ));

        let (ford_response, mut missing_key) = valid_ford_download_response();
        missing_key[0].1 = None;
        assert_verification_failed(validate_preauthorized_download_response(
            &ford_response,
            &missing_key,
        ));

        let (mut missing_ford_meta, requested) = valid_ford_download_response();
        missing_ford_meta.containers[0].chunks[1].encryption = None;
        assert_verification_failed(validate_preauthorized_download_response(
            &missing_ford_meta,
            &requested,
        ));

        let (mut missing_for_chunks, requested) = valid_ford_download_response();
        missing_for_chunks.containers[0].chunks[1]
            .encryption
            .as_mut()
            .unwrap()
            .for_chunks = None;
        assert_verification_failed(validate_preauthorized_download_response(
            &missing_for_chunks,
            &requested,
        ));
    }

    #[test]
    fn preauthorized_metadata_cardinality_and_encoded_body_are_bounded() {
        let mut authorization_body =
            opaque_authorization_body(MAX_PREAUTHORIZED_DOWNLOAD_AUTHORIZATION_BYTES);
        assert!(validate_preauthorized_authorization_body(&authorization_body).is_ok());
        authorization_body.push(0);
        assert_verification_failed(validate_preauthorized_authorization_body(
            &authorization_body,
        ));

        let (response, requested) = valid_download_response();
        let container = response.containers[0].clone();
        let reference = response.references[0].clone();
        let chunk = container.chunks[0].clone();

        let mut too_many_containers = response.clone();
        too_many_containers.containers =
            vec![container.clone(); MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS + 1];
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_containers,
            &requested,
        ));

        let mut too_many_references = response.clone();
        too_many_references.references =
            vec![reference.clone(); MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES + 1];
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_references,
            &requested,
        ));

        let mut too_many_container_chunks = response.clone();
        too_many_container_chunks.containers[0].chunks =
            vec![chunk.clone(); MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER + 1];
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_container_chunks,
            &requested,
        ));

        let mut too_many_total_chunks = response.clone();
        let mut zero_chunk = chunk.clone();
        zero_chunk.meta.as_mut().unwrap().size = 0;
        too_many_total_chunks.containers = [
            MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER,
            MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER,
            1,
        ]
        .into_iter()
        .map(|count| ProtoContainer {
            chunks: vec![zero_chunk.clone(); count],
            ..container.clone()
        })
        .collect();
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_total_chunks,
            &requested,
        ));

        let mut too_many_headers = response.clone();
        too_many_headers.containers[0]
            .request
            .as_mut()
            .unwrap()
            .headers = vec![
            Header {
                name: "x-mmcs-test".to_owned(),
                value: "value".to_owned(),
            };
            MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST + 1
        ];
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_headers,
            &requested,
        ));

        let mut too_many_chunk_references = response;
        too_many_chunk_references.references[0].chunk_references =
            vec![chunk_reference(0, 0); MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES + 1];
        assert_verification_failed(validate_preauthorized_download_response(
            &too_many_chunk_references,
            &requested,
        ));
    }

    #[test]
    fn protobuf_wire_preflight_enforces_nested_cardinality_at_and_over_limits() {
        let root_from_f1 = |f1: Vec<u8>| wrap_test_message(1, &f1);

        let containers = repeated_empty_test_messages(1, MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS);
        assert!(validate_preauthorized_authorization_body(&root_from_f1(containers)).is_ok());
        let too_many_containers =
            repeated_empty_test_messages(1, MAX_PREAUTHORIZED_DOWNLOAD_CONTAINERS + 1);
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            too_many_containers,
        )));

        let references = repeated_empty_test_messages(2, MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES);
        assert!(validate_preauthorized_authorization_body(&root_from_f1(references)).is_ok());
        let too_many_references =
            repeated_empty_test_messages(2, MAX_PREAUTHORIZED_DOWNLOAD_REFERENCES + 1);
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            too_many_references,
        )));

        let chunks =
            repeated_empty_test_messages(5, MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER);
        let one_full_container = wrap_test_message(1, &chunks);
        assert!(
            validate_preauthorized_authorization_body(&root_from_f1(one_full_container)).is_ok()
        );
        let too_many_chunks =
            repeated_empty_test_messages(5, MAX_PREAUTHORIZED_DOWNLOAD_CHUNKS_PER_CONTAINER + 1);
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            wrap_test_message(1, &too_many_chunks),
        )));

        let full_container = wrap_test_message(1, &chunks);
        let mut maximum_total_chunks = Vec::new();
        maximum_total_chunks.extend_from_slice(&full_container);
        maximum_total_chunks.extend_from_slice(&full_container);
        assert!(
            validate_preauthorized_authorization_body(&root_from_f1(maximum_total_chunks)).is_ok()
        );
        let mut too_many_total_chunks = Vec::new();
        too_many_total_chunks.extend_from_slice(&full_container);
        too_many_total_chunks.extend_from_slice(&full_container);
        append_test_message(
            &mut too_many_total_chunks,
            1,
            &repeated_empty_test_messages(5, 1),
        );
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            too_many_total_chunks,
        )));

        let headers =
            repeated_empty_test_messages(8, MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST);
        let request = wrap_test_message(1, &headers);
        let container = wrap_test_message(1, &request);
        assert!(validate_preauthorized_authorization_body(&root_from_f1(container)).is_ok());
        let too_many_headers =
            repeated_empty_test_messages(8, MAX_PREAUTHORIZED_DOWNLOAD_HEADERS_PER_REQUEST + 1);
        let request = wrap_test_message(1, &too_many_headers);
        let container = wrap_test_message(1, &request);
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            container,
        )));

        let chunk_references =
            repeated_empty_test_messages(2, MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES);
        let reference = wrap_test_message(2, &chunk_references);
        assert!(validate_preauthorized_authorization_body(&root_from_f1(reference)).is_ok());
        let too_many_chunk_references =
            repeated_empty_test_messages(2, MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES + 1);
        let reference = wrap_test_message(2, &too_many_chunk_references);
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            reference,
        )));

        let mut aggregate_references = Vec::new();
        for _ in 0..(MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES
            / MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES)
        {
            append_test_message(&mut aggregate_references, 2, &chunk_references);
        }
        assert!(validate_preauthorized_authorization_body(&root_from_f1(
            aggregate_references.clone(),
        ))
        .is_ok());
        append_test_message(
            &mut aggregate_references,
            2,
            &repeated_empty_test_messages(2, 1),
        );
        assert_verification_failed(validate_preauthorized_authorization_body(&root_from_f1(
            aggregate_references,
        )));
    }

    #[test]
    fn protobuf_wire_preflight_rejects_malformed_and_overlong_nested_varints() {
        for malformed in [
            vec![0x80],
            vec![0x8a, 0x00, 0x00],
            vec![0x0a, 0x80, 0x00],
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
        ] {
            assert_verification_failed(validate_preauthorized_authorization_body(&malformed));
        }

        let malformed_chunk_reference = vec![0x08, 0x80, 0x00];
        let reference = wrap_test_message(2, &malformed_chunk_reference);
        let f1 = wrap_test_message(2, &reference);
        assert_verification_failed(validate_preauthorized_authorization_body(
            &wrap_test_message(1, &f1),
        ));

        let truncated_chunk_reference = vec![0x08, 0x80];
        let reference = wrap_test_message(2, &truncated_chunk_reference);
        let f1 = wrap_test_message(2, &reference);
        assert_verification_failed(validate_preauthorized_authorization_body(
            &wrap_test_message(1, &f1),
        ));
    }

    #[test]
    fn decoded_response_enforces_aggregate_chunk_reference_limit() {
        let (mut response, _) = valid_download_response();
        response.references.clear();
        let mut requested = Vec::new();
        for index in 0..(MAX_PREAUTHORIZED_DOWNLOAD_TOTAL_CHUNK_REFERENCES
            / MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES)
        {
            let checksum = vec![0x40 + index as u8; 21];
            response.references.push(ChunkReferences {
                file_checksum: checksum.clone(),
                chunk_references: vec![
                    chunk_reference(0, 0);
                    MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_REFERENCES
                ],
                ..Default::default()
            });
            requested.push((checksum, None));
        }
        assert!(validate_preauthorized_download_response(&response, &requested).is_ok());

        let checksum = vec![0x7f; 21];
        response.references.push(ChunkReferences {
            file_checksum: checksum.clone(),
            chunk_references: vec![chunk_reference(0, 0)],
            ..Default::default()
        });
        requested.push((checksum, None));
        assert_verification_failed(validate_preauthorized_download_response(
            &response, &requested,
        ));
    }

    #[test]
    fn preauthorized_container_layout_is_monotonic_nonoverlapping_and_bounded() {
        let (response, requested) = valid_download_response();

        let mut oversized_end = response.clone();
        let meta = oversized_end.containers[0].chunks[0].meta.as_mut().unwrap();
        meta.offset = MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES;
        meta.size = 1;
        assert_verification_failed(validate_preauthorized_download_response(
            &oversized_end,
            &requested,
        ));

        let mut overflowing_end = response.clone();
        let meta = overflowing_end.containers[0].chunks[0]
            .meta
            .as_mut()
            .unwrap();
        meta.offset = u64::MAX;
        meta.size = 1;
        assert_verification_failed(validate_preauthorized_download_response(
            &overflowing_end,
            &requested,
        ));

        let mut overlap = response.clone();
        let mut second = overlap.containers[0].chunks[0].clone();
        second.meta.as_mut().unwrap().offset = 8;
        overlap.containers[0].chunks.push(second);
        assert_verification_failed(validate_preauthorized_download_response(
            &overlap, &requested,
        ));

        let mut bounded_gap = response;
        bounded_gap.containers[0].chunks[0]
            .meta
            .as_mut()
            .unwrap()
            .offset = 1024;
        assert!(validate_preauthorized_download_response(&bounded_gap, &requested).is_ok());
    }

    #[test]
    fn requested_protection_key_is_optional_without_ford_reference() {
        let (response_without_ford, mut requested_with_key) = valid_download_response();
        requested_with_key[0].1 = Some(vec![0x55; 32]);
        assert!(validate_preauthorized_download_response(
            &response_without_ford,
            &requested_with_key,
        )
        .is_ok());

        let (response_with_ford, requested_with_key) = valid_ford_download_response();
        assert!(
            validate_preauthorized_download_response(&response_with_ford, &requested_with_key,)
                .is_ok()
        );

        let mut missing_key = requested_with_key.clone();
        missing_key[0].1 = None;
        assert_verification_failed(validate_preauthorized_download_response(
            &response_with_ford,
            &missing_key,
        ));

        let mut wrong_key = requested_with_key;
        wrong_key[0].1.as_mut().unwrap()[0] ^= 0x01;
        assert_verification_failed(validate_preauthorized_download_response(
            &response_with_ford,
            &wrong_key,
        ));
    }

    #[test]
    fn malformed_response_checksum_and_encryption_lengths_return_errors() {
        let (mut bad_checksum, requested) = valid_download_response();
        bad_checksum.containers[0].chunks[0]
            .meta
            .as_mut()
            .unwrap()
            .checksum = vec![0; 20];
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_checksum,
            &requested,
        ));

        let (bad_reference, mut bad_requested_checksum) = valid_download_response();
        bad_requested_checksum[0].0 = vec![0; 20];
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_reference,
            &bad_requested_checksum,
        ));

        let (mut bad_v1_key, requested) = valid_download_response();
        bad_v1_key.containers[0].chunks[0]
            .meta
            .as_mut()
            .unwrap()
            .encryption_key = Some(vec![0; 16]);
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_v1_key,
            &requested,
        ));

        let (mut bad_ford_checksum, requested) = valid_ford_download_response();
        bad_ford_checksum.containers[0].chunks[1]
            .encryption
            .as_mut()
            .unwrap()
            .for_chunks
            .as_mut()
            .unwrap()
            .keys_container = vec![0; 20];
        assert_verification_failed(validate_preauthorized_download_response(
            &bad_ford_checksum,
            &requested,
        ));
    }

    #[test]
    fn overlarge_data_and_ford_chunks_fail_before_transfer() {
        let (mut oversized_data, requested) = valid_download_response();
        oversized_data.containers[0].chunks[0]
            .meta
            .as_mut()
            .unwrap()
            .size = MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES + 1;
        assert_verification_failed(validate_preauthorized_download_response(
            &oversized_data,
            &requested,
        ));

        let (mut oversized_ford, requested) = valid_ford_download_response();
        oversized_ford.containers[0].chunks[1]
            .encryption
            .as_mut()
            .unwrap()
            .size = (MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES + 1) as u32;
        assert_verification_failed(validate_preauthorized_download_response(
            &oversized_ford,
            &requested,
        ));
    }

    #[test]
    fn aggregate_chunk_limit_counts_ford_referenced_bytes() {
        let (mut boundary, requested) = valid_download_response();
        boundary.containers[0].chunks = (0u8..8)
            .map(|index| ChunkWrapper {
                meta: Some(ChunkMeta {
                    checksum: vec![index + 1; 21],
                    size: MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES,
                    offset: u64::from(index) * MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES,
                    ..Default::default()
                }),
                encryption: None,
            })
            .collect();
        assert!(validate_preauthorized_download_response(&boundary, &requested).is_ok());

        let (ford_response, _) = valid_ford_download_response();
        let mut ford_chunk = ford_response.containers[0].chunks[1].clone();
        let encryption = ford_chunk.encryption.as_mut().unwrap();
        encryption.offset = 0;
        encryption.size = 1;
        boundary.containers.push(ProtoContainer {
            request: Some(chunk_request("GET", "https")),
            chunks: vec![ford_chunk],
            ..Default::default()
        });
        boundary.references[0].ford_reference = Some(chunk_reference(1, 0));
        let requested_with_ford_key = vec![(requested[0].0.clone(), Some(vec![0x55; 32]))];
        assert_verification_failed(validate_preauthorized_download_response(
            &boundary,
            &requested_with_ford_key,
        ));
    }

    #[test]
    fn malformed_response_empty_or_mismatched_targets_return_errors() {
        let (response, requested) = valid_download_response();

        let mut empty_containers = response.clone();
        empty_containers.containers.clear();
        assert_verification_failed(validate_preauthorized_download_response(
            &empty_containers,
            &requested,
        ));

        let mut empty_references = response.clone();
        empty_references.references.clear();
        assert_verification_failed(validate_preauthorized_download_response(
            &empty_references,
            &requested,
        ));

        let mut empty_target = response.clone();
        empty_target.references[0].chunk_references.clear();
        assert_verification_failed(validate_preauthorized_download_response(
            &empty_target,
            &requested,
        ));

        let mut mismatched_target = response;
        mismatched_target.references[0].file_checksum = vec![0x99; 21];
        assert_verification_failed(validate_preauthorized_download_response(
            &mismatched_target,
            &requested,
        ));
    }

    #[test]
    fn extra_bundled_file_reference_is_ignored_when_requested_file_is_present() {
        let (mut response, requested) = valid_download_response();
        let mut sibling = response.references[0].clone();
        sibling.file_checksum = vec![0x99; 21];
        response.containers[0].chunks.push(ChunkWrapper {
            meta: Some(ChunkMeta {
                checksum: vec![0x44; 21],
                size: 8,
                offset: 16,
                ..Default::default()
            }),
            encryption: None,
        });
        sibling.chunk_references = vec![chunk_reference(0, 1)];
        // Put the unrequested sibling first to pin the live CloudKit ordering
        // that previously failed before reaching the requested reference.
        response.references.insert(0, sibling);

        assert!(validate_preauthorized_download_response(&response, &requested).is_ok());
    }

    #[test]
    fn malformed_bundled_sibling_ford_reference_is_rejected() {
        let (mut response, requested) = valid_download_response();
        let mut sibling = response.references[0].clone();
        sibling.file_checksum = vec![0x99; 21];
        sibling.ford_reference = Some(chunk_reference(99, 0));
        response.references.insert(0, sibling);

        assert_verification_failed(validate_preauthorized_download_response(
            &response, &requested,
        ));
    }

    #[test]
    fn malformed_ford_ciphertext_returns_errors_instead_of_panicking() {
        for short_len in [0, 1, 16, 17] {
            assert_verification_failed(decode_ford_item(&vec![0; short_len], &[0x55; 32]));
        }

        let mut authentication_failure = vec![0; 33];
        authentication_failure[0] = 4;
        assert_verification_failed(decode_ford_item(&authentication_failure, &[0x55; 32]));
        assert_verification_failed(require_ford_item(FordChunk::default()));
    }

    #[test]
    fn malformed_ford_item_lengths_and_reference_counts_return_errors() {
        let (response, _) = valid_download_response();
        let references = &response.references[0].chunk_references;

        let mut keymap = HashMap::new();
        assert_verification_failed(add_ford_item_keys(
            &mut keymap,
            FordItem::default(),
            references,
            &response.containers,
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
        ));

        let invalid_key = FordItem {
            chunks: vec![FordChunkItem {
                key: vec![0; 32],
                chunk_len: vec![0; 4],
            }],
            ..Default::default()
        };
        assert_verification_failed(add_ford_item_keys(
            &mut keymap,
            invalid_key,
            references,
            &response.containers,
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
        ));

        let invalid_length = FordItem {
            chunks: vec![FordChunkItem {
                key: vec![0; 33],
                chunk_len: vec![0; 3],
            }],
            ..Default::default()
        };
        assert_verification_failed(add_ford_item_keys(
            &mut keymap,
            invalid_length,
            references,
            &response.containers,
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
        ));

        let oversized_plaintext = FordItem {
            chunks: vec![FordChunkItem {
                key: vec![0; 33],
                chunk_len: ((MAX_PREAUTHORIZED_DOWNLOAD_CHUNK_BYTES as u32) + 1)
                    .to_le_bytes()
                    .to_vec(),
            }],
            ..Default::default()
        };
        assert_verification_failed(add_ford_item_keys(
            &mut keymap,
            oversized_plaintext,
            references,
            &response.containers,
            MMCSGetNetworkPolicy::PreauthorizedDownloadOnly,
        ));
    }

    #[test]
    fn v1_and_unencrypted_chunks_verify_protocol_signature_before_use() {
        let plaintext = b"verified MMCS legacy chunk".to_vec();
        let (id, key) = gen_chunk_sig(&plaintext, 0x81);

        let unencrypted = ChunkDesc {
            id,
            size: plaintext.len(),
            key: ChunkEncryption::None,
            offset: None,
        };
        assert_eq!(unencrypted.decrypt(plaintext.clone()).unwrap(), plaintext);
        assert_eq!(unencrypted.encrypt(plaintext.clone()).unwrap(), plaintext);
        let mut corrupted_plaintext = plaintext.clone();
        corrupted_plaintext[0] ^= 0x01;
        assert_verification_failed(unencrypted.decrypt(corrupted_plaintext.clone()));
        assert_verification_failed(unencrypted.encrypt(corrupted_plaintext));

        let encrypted = ChunkDesc {
            key: ChunkEncryption::V1(key),
            ..unencrypted
        };
        let ciphertext = encrypted.encrypt(plaintext.clone()).unwrap();
        assert_eq!(encrypted.decrypt(ciphertext.clone()).unwrap(), plaintext);
        let mut corrupted_ciphertext = ciphertext;
        corrupted_ciphertext[0] ^= 0x01;
        assert_verification_failed(encrypted.decrypt(corrupted_ciphertext));

        let wrong_identifier = ChunkDesc {
            id: [0x99; 21],
            ..encrypted
        };
        assert_verification_failed(
            wrong_identifier.decrypt(
                encrypted
                    .encrypt(b"verified MMCS legacy chunk".to_vec())
                    .unwrap(),
            ),
        );
    }

    #[tokio::test]
    async fn ford_v2_source_authenticates_before_plaintext_target_write() {
        let plaintext = b"verified MMCS Ford V2 chunk".to_vec();
        let prepared = prepare_put_v2(
            FileContainer::new(Cursor::new(plaintext.clone())),
            &[0x42; 32],
        )
        .await
        .unwrap();
        let source_desc = prepared.chunk_sigs[0];
        let ciphertext = source_desc.encrypt(plaintext.clone()).unwrap();

        // A Ford V2 identifier is HMAC-derived and intentionally is not a
        // legacy double-SHA chunk signature.
        let legacy_target = ChunkDesc {
            key: ChunkEncryption::None,
            ..source_desc
        };
        assert_verification_failed(legacy_target.encrypt(plaintext.clone()));

        let mut source = ChunkedContainer::new(
            vec![ChunkDesc {
                size: ciphertext.len(),
                ..source_desc
            }],
            FileContainer::new(Cursor::new(ciphertext.clone())),
        );
        let mut target = ChunkedContainer::new(
            vec![ChunkDesc {
                key: ChunkEncryption::VerifiedRemotePlaintext,
                ..source_desc
            }],
            FileContainer::new(Cursor::new(Vec::new())),
        );
        let verified_chunk = source.read_next().await.unwrap();
        target.write_chunk(&verified_chunk).await.unwrap();
        assert!(source.complete());
        assert!(target.complete());
        assert_eq!(target.container.inner.get_ref(), &plaintext);

        // Destination-only mode must never become a source-side bypass.
        assert_verification_failed(
            ChunkDesc {
                key: ChunkEncryption::VerifiedRemotePlaintext,
                ..source_desc
            }
            .decrypt(plaintext.clone()),
        );

        let mut corrupted_ciphertext = ciphertext.clone();
        corrupted_ciphertext[0] ^= 0x01;
        assert_verification_failed(source_desc.decrypt(corrupted_ciphertext));

        let ChunkEncryption::V2(mut wrong_key, plaintext_len) = source_desc.key else {
            panic!("Ford fixture did not create a V2 chunk");
        };
        wrong_key[1] ^= 0x01;
        assert_verification_failed(
            ChunkDesc {
                key: ChunkEncryption::V2(wrong_key, plaintext_len),
                ..source_desc
            }
            .decrypt(ciphertext),
        );
    }

    #[test]
    fn malformed_v2_chunk_integrity_returns_error_instead_of_asserting() {
        let chunk = ChunkDesc {
            id: [0; 21],
            size: 1,
            key: ChunkEncryption::V2([0; 33], 1u32.to_le_bytes()),
            offset: None,
        };
        assert_verification_failed(chunk.decrypt(vec![0]));

        let oversized_plaintext = ChunkDesc {
            key: ChunkEncryption::V2([0; 33], 2u32.to_le_bytes()),
            ..chunk
        };
        assert_verification_failed(oversized_plaintext.decrypt(vec![0]));
    }

    #[test]
    fn download_only_actual_response_bytes_have_one_shared_hard_ceiling() {
        let counter = AtomicU64::new(MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES - 1);
        assert!(record_preauthorized_response_bytes(&counter, 1).is_ok());
        assert_eq!(
            counter.load(Ordering::Relaxed),
            MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES
        );
        assert_verification_failed(record_preauthorized_response_bytes(&counter, 1));
        assert_eq!(
            counter.load(Ordering::Relaxed),
            MAX_PREAUTHORIZED_DOWNLOAD_RESPONSE_BYTES
        );
    }

    struct BoundedSkipProbe {
        remaining: usize,
        largest_read: usize,
    }

    #[async_trait]
    impl Container for BoundedSkipProbe {}

    #[async_trait]
    impl ReadContainer for BoundedSkipProbe {
        async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
            self.largest_read = self.largest_read.max(len);
            let read = len.min(self.remaining);
            self.remaining -= read;
            Ok(vec![0; read])
        }
    }

    #[tokio::test]
    async fn source_gap_skip_never_buffers_the_attacker_sized_gap() {
        let gap = MMCS_BOUNDED_SKIP_BYTES * 3 + 1;
        let mut source = BoundedSkipProbe {
            remaining: gap,
            largest_read: 0,
        };
        source.skip(gap).await.unwrap();
        assert_eq!(source.remaining, 0);
        assert!(source.largest_read <= MMCS_BOUNDED_SKIP_BYTES);
    }

    #[tokio::test]
    async fn malformed_descending_source_offset_returns_error() {
        let mut source = ChunkedContainer::new(
            vec![ChunkDesc {
                id: [0; 21],
                size: 1,
                key: ChunkEncryption::None,
                offset: Some(0),
            }],
            FileContainer::new(Cursor::new(vec![0])),
        );
        source.current_offset = 1;
        assert_verification_failed(source.read_next().await);
    }
}
