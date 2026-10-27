//! Pure pre-prost validation of one ORIGINAL, unframed ResponseOperation.
//! Returns the exact Record bytes at field 211 -> field 1, never a reencoding.
//! None means a validated non-success frame has no retrieve payload; it is NOT
//! NotFound proof. The caller must still match the operation UUID and classify
//! the status, then bind record/account/zone/ETag and inspect required fields.
//!
//! Validates identity/result/error branches even when no record is returned.
//! Record submessages use the checked-in cloudkit.proto field numbers. Unknown
//! tags, duplicate singulars, wrong wire types, truncation and numeric narrowing
//! fail with BadMsg. Field-name uniqueness and type/payload consistency remain
//! the inspector's job. Absent and explicit empty values are never normalized.
//!
//! Scope is conservative: other response payloads, Record.shareInfo (16), and
//! nonempty Record.protectionInfoKeysToRemove (31) are unsupported. Empty31 is
//! preserved; no key removal or protection-tag instruction is applied or ignored.
//! The unrelated ResponseOperation.header payload is opaque;
//! it cannot provide identity or a result and is still decoded by the caller.
//! bytesValue/PCS/asset bytes are opaque, including encrypted EncryptedValue.
//! Decrypted scalar and MessageProto validation belongs to the inspector.
//!
//! No I/O, decryption, logging or authority. At most 8 MiB input, 4096 visited
//! fields, 16 active message levels; one final Record-sized allocation only.
//! Any legal field order and non-minimal, non-overflowing varints are accepted.

use crate::PushError;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_FIELDS: usize = 4096;
const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Schema {
    Response,
    Operation,
    Result,
    Error,
    ClientError,
    ServerError,
    Extension,
    Retrieve,
    Record,
    RecordId,
    ZoneId,
    Identifier,
    Name,
    Dates,
    Date,
    Field,
    Value,
    Coordinate,
    Reference,
    Asset,
    Package,
    Protection,
    ProtectionKeysToRemove,
    ProtectionRemovalKey,
    StableUrl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireFailureKind {
    FrameLimit,
    FieldLimit,
    DepthLimit,
    InvalidKey,
    UnknownField,
    WrongWireType,
    DuplicateSingular,
    InvalidScalar,
    InvalidLength,
    TruncatedFixed64,
    InvalidText,
    InvalidOperationIdentity,
    OperationKind,
    ResultCode,
    ErrorCode,
    InvalidShape,
    ResultConflict,
    UnsupportedProtectionMetadata,
}

/// Protocol structure only. No response values, identifiers or error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReceivedWireDiagnostic {
    schema: Schema,
    field: Option<u32>,
    reason: WireFailureKind,
}

impl std::fmt::Display for ReceivedWireDiagnostic {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "schema={:?} field={:?} reason={:?}", self.schema, self.field, self.reason)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Varint,
    U32,
    I32,
    Bool,
    Bytes,
    Text,
    Fixed64,
    Message(Schema),
}

impl Kind {
    fn wire(self) -> u64 {
        match self {
            Self::Varint | Self::U32 | Self::I32 | Self::Bool => 0,
            Self::Fixed64 => 1,
            Self::Bytes | Self::Text | Self::Message(_) => 2,
        }
    }
}

/// Closed schema table, not a generic unknown-field skipper.
fn rule(schema: Schema, tag: u64) -> Result<(Kind, bool), PushError> {
    use Kind::*;
    use Schema::*;
    let kind = match (schema, tag) {
        (Response, 1) => U32,
        (Response, 2) => Message(Operation),
        (Response, 3) => Message(Result),
        (Response, 4) => Bytes,
        (Response, 211) => Message(Retrieve),
        (Operation, 1) => Text,
        (Operation, 2) => U32,
        (Operation, 3 | 4) => Bool,
        (Result, 1) => U32,
        (Result, 2) => Message(Error),
        (Error, 1) => Message(ClientError),
        (Error, 2) => Message(ServerError),
        (Error, 3) => I32,
        (Error, 4..=6) => Text,
        (Error, 7) => Message(Extension),
        (ClientError | ServerError, 1) => U32,
        (Extension, 1) => Text,
        (Extension, 2) => U32,
        (Extension, 3) => Bytes,
        (Retrieve, 1) => Message(Record),
        (Retrieve, 2) => Bool,
        (Record, 1 | 11) => Text,
        (Record, 2 | 8) => Message(RecordId), // ShareIdentifier has the same schema.
        (Record, 3) => Message(Name),
        (Record, 4 | 9) => Message(Identifier),
        (Record, 5) => Message(Dates),
        (Record, 7 | 12) => return Ok((Message(Field), true)),
        (Record, 10) => return Ok((Text, true)),
        (Record, 13) => Message(Protection),
        (Record, 15) => U32,
        (Record, 22) => Message(StableUrl),
        (Record, 24) => Bytes,
        // Published iOS26.1/23B85 CKDPRecordReadFrom case0x1f stores the singular
        // CKDPProtectionInfoKeysToRemove at offset136; CKDPRecord.copyWithZone
        // binds136 to that property. Decoder sub_2253101B8 defines the nested
        // fields below. Source: EthanArbuckle/iPhone18-3_26.1_23B85_Restore,
        // commit90aa0cfe59d9682b4265e1354c8b19ec3c7823ab, CloudKitDaemon_01/13.mm.
        // This is strict read grammar only: every nonempty message is held
        // below before returning raw bytes, so it cannot become Found/staged.
        (Record, 31) => Message(ProtectionKeysToRemove),
        (ProtectionKeysToRemove, 1) => return Ok((Message(ProtectionRemovalKey), true)),
        (ProtectionKeysToRemove, 2) => Text,
        (ProtectionRemovalKey, 1) => Bytes,
        (ProtectionRemovalKey, 2) => I32,
        (RecordId, 1) => Message(Identifier),
        (RecordId, 2) => Message(ZoneId),
        (ZoneId, 1 | 2) => Message(Identifier),
        (ZoneId, 3) | (Identifier, 2) => U32,
        (Identifier | Name, 1) => Text,
        (Dates, 1 | 2) => Message(Date),
        (Date, 1) => Fixed64,
        (Field, 1) => Message(Name),
        (Field, 2) => Message(Value),
        (Value, 1) => U32,
        (Value, 2) => Bytes,
        (Value, 4) => Varint, // int64: preserve all 64 bits, including flags.
        (Value, 5) => Fixed64,
        (Value, 6) => Message(Date),
        (Value, 7) => Text,
        (Value, 8) => Message(Coordinate),
        (Value, 9) => Message(Reference),
        (Value, 10) => Message(Asset),
        (Value, 11) => return Ok((Message(Value), true)),
        (Value, 12) => Message(Package),
        (Value, 13) => Bool,
        (Coordinate, 1..=7) => Fixed64,
        (Coordinate, 8) => Message(Date),
        (Reference, 1) => U32,
        (Reference, 2) => Message(RecordId),
        (Asset, 1 | 5 | 7..=9 | 11 | 13 | 21) => Text,
        (Asset, 2 | 3 | 6 | 12 | 17) => Bytes,
        (Asset, 4 | 14 | 18) => Varint,
        (Asset, 10) => Message(RecordId),
        (Asset, 15) => Message(Protection),
        (Package, 1) => Message(Asset),
        (Package, 2) => return Ok((Message(Asset), true)),
        (Protection, 1) => Bytes,
        (Protection, 2) => Text,
        (StableUrl, 1 | 5) => Text,
        (StableUrl, 2..=4) => Bytes,
        _ => return Err(PushError::BadMsg),
    };
    Ok((kind, false))
}

struct Level<'a> {
    schema: Schema,
    bytes: &'a [u8],
    pos: usize,
    seen: u32,
}

impl<'a> Level<'a> {
    fn new(schema: Schema, bytes: &'a [u8]) -> Self {
        Self {
            schema,
            bytes,
            pos: 0,
            seen: 0,
        }
    }

    fn finish(&self) -> Result<(), PushError> {
        use Schema::*;
        let required = match self.schema {
            Response => (1 << 2) | (1 << 3),
            Operation | Result | ClientError | ServerError | Retrieve => 1 << 1,
            _ => 0, // Required record content is checked after raw extraction.
        };
        // Multiple error classes must not let server NOT_FOUND win over a
        // conflicting client/extension failure.
        let error_classes = self.seen & ((1 << 1) | (1 << 2) | (1 << 7));
        if self.seen & required != required
            || (self.schema == Error && error_classes.count_ones() > 1)
        {
            return Err(PushError::BadMsg);
        }
        Ok(())
    }
}

fn varint(bytes: &[u8], pos: &mut usize) -> Result<u64, PushError> {
    let mut value = 0;
    for shift in 0..10 {
        let byte = *bytes.get(*pos).ok_or(PushError::BadMsg)?;
        *pos += 1;
        if shift == 9 && byte > 1 {
            return Err(PushError::BadMsg);
        }
        value |= u64::from(byte & 0x7f) << (7 * shift);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(PushError::BadMsg)
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], PushError> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or(PushError::BadMsg)?;
    let value = &bytes[*pos..end];
    *pos = end;
    Ok(value)
}

pub(super) fn received_record_wire(frame: &[u8]) -> Result<Option<Vec<u8>>, PushError> {
    received_record_wire_diagnostic(frame).map_err(|_| PushError::BadMsg)
}

pub(super) fn received_record_wire_diagnostic(
    frame: &[u8],
) -> Result<Option<Vec<u8>>, ReceivedWireDiagnostic> {
    let mut diagnostic = ReceivedWireDiagnostic {
        schema: Schema::Response, field: None, reason: WireFailureKind::FrameLimit,
    };
    parse_received_record_wire(frame, &mut diagnostic).map_err(|_| diagnostic)
}

fn parse_received_record_wire(
    frame: &[u8],
    diagnostic: &mut ReceivedWireDiagnostic,
) -> Result<Option<Vec<u8>>, PushError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(PushError::BadMsg);
    }
    let mut levels = Vec::with_capacity(MAX_DEPTH);
    levels.push(Level::new(Schema::Response, frame));
    let mut remaining = MAX_FIELDS;
    let mut record = None;
    let mut result_code = 0;
    let mut has_error = false;
    let mut server_code = None;
    while let Some(level) = levels.last_mut() {
        diagnostic.schema = level.schema;
        diagnostic.field = None;
        if level.pos == level.bytes.len() {
            diagnostic.reason = WireFailureKind::InvalidShape;
            level.finish()?;
            // A present key (even an empty entry) or tag (even empty text) is
            // protection-management metadata. Cached decryption is not proof
            // that ignoring it is safe. Traverse it first, then hold before
            // the strict fetch can return Found or authorize source staging.
            if level.schema == Schema::ProtectionKeysToRemove && level.seen != 0 {
                diagnostic.reason = WireFailureKind::UnsupportedProtectionMetadata;
                return Err(PushError::BadMsg);
            }
            levels.pop();
            continue;
        }
        diagnostic.reason = WireFailureKind::FieldLimit;
        remaining = remaining.checked_sub(1).ok_or(PushError::BadMsg)?;
        diagnostic.reason = WireFailureKind::InvalidKey;
        let key = varint(level.bytes, &mut level.pos)?;
        let tag = key >> 3;
        if tag == 0 || tag > 0x1fff_ffff {
            return Err(PushError::BadMsg);
        }
        diagnostic.field = Some(tag as u32);
        diagnostic.reason = WireFailureKind::UnknownField;
        let (kind, repeated) = rule(level.schema, tag)?;
        diagnostic.reason = WireFailureKind::WrongWireType;
        if key & 7 != kind.wire() {
            return Err(PushError::BadMsg);
        }
        // Every admitted tag fits 1..=31 except ResponseOperation.211.
        // The31 sentinel is local to each schema level, never shared by
        // Response.211 and its nested Record.31.
        let bit = 1u32 << if tag == 211 { 31 } else { tag as u32 };
        diagnostic.reason = WireFailureKind::DuplicateSingular;
        if !repeated && level.seen & bit != 0 {
            return Err(PushError::BadMsg);
        }
        level.seen |= bit;
        if kind.wire() == 0 {
            diagnostic.reason = WireFailureKind::InvalidScalar;
            let value = varint(level.bytes, &mut level.pos)?;
            if matches!(kind, Kind::U32) && value > u64::from(u32::MAX)
                || matches!(kind, Kind::Bool) && value > 1
                || matches!(kind, Kind::I32)
                    && value > i32::MAX as u64
                    && value < i32::MIN as i64 as u64
            {
                return Err(PushError::BadMsg);
            }
            match (level.schema, tag) {
                (Schema::ProtectionRemovalKey, 2) if !(1..=3).contains(&value) => {
                    return Err(PushError::BadMsg);
                }
                (Schema::Operation, 2) if value != 211 => {
                    diagnostic.reason = WireFailureKind::OperationKind;
                    return Err(PushError::BadMsg);
                }
                (Schema::Result, 1) => {
                    if !(1..=4).contains(&value) {
                        diagnostic.reason = WireFailureKind::ResultCode;
                        return Err(PushError::BadMsg);
                    }
                    result_code = value;
                }
                (Schema::ServerError, 1) => {
                    if !matches!(value, 1..=4 | 6..=8) {
                        diagnostic.reason = WireFailureKind::ErrorCode;
                        return Err(PushError::BadMsg);
                    }
                    server_code = Some(value);
                }
                (Schema::ClientError, 1) if !matches!(value, 1..=43 | 46..=62) => {
                    diagnostic.reason = WireFailureKind::ErrorCode;
                    return Err(PushError::BadMsg)
                }
                _ => {}
            }
        } else if kind.wire() == 1 {
            diagnostic.reason = WireFailureKind::TruncatedFixed64;
            take(level.bytes, &mut level.pos, 8)?;
        } else {
            diagnostic.reason = WireFailureKind::InvalidLength;
            let len = usize::try_from(varint(level.bytes, &mut level.pos)?)
                .map_err(|_| PushError::BadMsg)?;
            let bytes = take(level.bytes, &mut level.pos, len)?;
            if matches!(kind, Kind::Text) {
                diagnostic.reason = WireFailureKind::InvalidText;
                std::str::from_utf8(bytes).map_err(|_| PushError::BadMsg)?;
                if level.schema == Schema::Operation
                    && tag == 1
                    && (bytes.is_empty() || bytes.len() > 128)
                {
                    diagnostic.reason = WireFailureKind::InvalidOperationIdentity;
                    return Err(PushError::BadMsg);
                }
            }
            if level.schema == Schema::Result && tag == 2 {
                has_error = true;
            }
            if level.schema == Schema::Retrieve && tag == 1 {
                record = Some(bytes);
            }
            if let Kind::Message(schema) = kind {
                if levels.len() == MAX_DEPTH {
                    diagnostic.reason = WireFailureKind::DepthLimit;
                    return Err(PushError::BadMsg);
                }
                levels.push(Level::new(schema, bytes));
            }
        }
    }
    // Success must carry a record and no error; failed/partial/indeterminate
    // frames must not also carry a record. NOT_FOUND is only meaningful with
    // explicit FAILURE, not an ambiguous PARTIAL/INDETERMINATE result.
    if (result_code == 1) != record.is_some()
        || (result_code == 1 && has_error)
        || (server_code == Some(3) && result_code != 3)
    {
        *diagnostic = ReceivedWireDiagnostic {
            schema: Schema::Response, field: None, reason: WireFailureKind::ResultConflict,
        };
        return Err(PushError::BadMsg);
    }
    Ok(record.map(<[u8]>::to_vec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudkit_proto::{Record, ResponseOperation};
    use prost::Message;

    fn vi(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 128 {
            out.push((value as u8 & 127) | 128);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }
    fn number(tag: u64, value: u64) -> Vec<u8> {
        [vi(tag << 3), vi(value)].concat()
    }
    fn data(tag: u64, value: &[u8]) -> Vec<u8> {
        [vi((tag << 3) | 2), vi(value.len() as u64), value.to_vec()].concat()
    }
    fn fixed(tag: u64, value: f64) -> Vec<u8> {
        [vi((tag << 3) | 1), value.to_le_bytes().to_vec()].concat()
    }
    fn operation() -> Vec<u8> {
        [
            data(1, b"11111111-2222-4333-8444-555555555555"),
            number(2, 211),
        ]
        .concat()
    }
    fn frame(op: &[u8], result: &[u8], retrieve: Option<&[u8]>) -> Vec<u8> {
        let mut out = [data(2, op), data(3, result)].concat();
        if let Some(retrieve) = retrieve {
            out.extend(data(211, retrieve));
        }
        out
    }
    fn success(record: &[u8]) -> Vec<u8> {
        frame(&operation(), &number(1, 1), Some(&data(1, record)))
    }
    fn field(name: &str, value: &[u8]) -> Vec<u8> {
        [data(1, &data(1, name.as_bytes())), data(2, value)].concat()
    }
    fn record_with_value(value: &[u8]) -> Vec<u8> {
        data(7, &field("msgType", value))
    }
    fn failure(error: &[u8]) -> Vec<u8> {
        [number(1, 3), data(2, error)].concat()
    }
    fn not_found() -> Vec<u8> {
        failure(&data(2, &number(1, 3)))
    }
    fn rejected(frame: &[u8]) {
        assert!(matches!(
            received_record_wire(frame),
            Err(PushError::BadMsg)
        ));
    }

    #[test]
    fn diagnostics_identify_fixed_schema_rules_without_response_values() {
        let private = b"private-selector-credential-record";
        let unknown = success(&data(63, private));
        let duplicate = success(&[data(1, private), data(1, private)].concat());
        for (raw, expected) in [
            (unknown, ReceivedWireDiagnostic {
                schema: Schema::Record, field: Some(63), reason: WireFailureKind::UnknownField,
            }),
            (duplicate, ReceivedWireDiagnostic {
                schema: Schema::Record, field: Some(1), reason: WireFailureKind::DuplicateSingular,
            }),
            (success(&number(1, 1)), ReceivedWireDiagnostic {
                schema: Schema::Record, field: Some(1), reason: WireFailureKind::WrongWireType,
            }),
        ] {
            let diagnostic = received_record_wire_diagnostic(&raw).unwrap_err();
            assert_eq!(diagnostic, expected);
            assert!(!diagnostic.to_string().contains(std::str::from_utf8(private).unwrap()));
            assert!(matches!(received_record_wire(&raw), Err(PushError::BadMsg)));
        }
    }

    #[test]
    fn diagnostics_preserve_success_absence_and_all_existing_rejections() {
        let record = record_with_value(&[number(1, 20), data(2, &[0xff, 0]), number(13, 1)].concat());
        assert_eq!(received_record_wire_diagnostic(&success(&record)).unwrap(), Some(record));
        assert_eq!(received_record_wire_diagnostic(&frame(&operation(), &not_found(), None)).unwrap(), None);
        assert_eq!(received_record_wire_diagnostic(&frame(&operation(), &number(1, 1), None)),
            Err(ReceivedWireDiagnostic {schema: Schema::Response, field: None, reason: WireFailureKind::ResultConflict}));
    }

    #[test]
    fn exact_schema_path_extracts_original_record_with_system_metadata_and_flags() {
        let id = [data(1, b"synthetic"), number(2, 1)].concat();
        let zone = [data(1, &id), data(2, &id), number(3, 1)].concat();
        let record_id = [data(1, &id), data(2, &zone)].concat();
        let signed = [number(1, 7), number(4, i64::MIN as u64)].concat();
        let text = [number(1, 3), data(7, b"")].concat();
        // Intentionally invalid protobuf, but opaque ciphertext must survive.
        let encrypted = [number(1, 20), data(2, &[0xff, 0, 0x80]), number(13, 1)].concat();
        let date = fixed(1, 123.5);
        let record = [
            data(24, &[1, 2, 3, 4]),
            data(3, &data(1, b"MessageEncryptedV3")),
            data(7, &field("flags", &signed)),
            data(7, &field("sender", &text)),
            data(7, &field("msgProto", &encrypted)),
            data(2, &record_id),
            data(1, b"etag"),
            data(4, &id),
            data(9, &id),
            data(5, &[data(1, &date), data(2, &date)].concat()),
            data(10, b"old-a"),
            data(10, b"old-b"),
            data(11, b"device"),
            data(12, &field("plugin", &text)),
            data(12, &field("plugin2", &text)),
            data(8, &record_id),
            number(15, 1),
            data(13, &[data(1, b"pcs"), data(2, b"tag")].concat()),
            data(22, &[data(1, b"route"), data(2, b"opaque")].concat()),
        ]
        .concat();
        let framed = success(&record);
        assert_eq!(received_record_wire(&framed).unwrap(), Some(record.clone()));
        let decoded = Record::decode(record.as_slice()).unwrap();
        let response = ResponseOperation::decode(framed.as_slice()).unwrap();
        assert_eq!(
            response.record_retrieve_response.unwrap().record.unwrap(),
            decoded
        );
        assert_eq!(
            decoded.record_field[0].value.as_ref().unwrap().signed_value,
            Some(i64::MIN)
        );
        assert_eq!(
            decoded.record_field[1]
                .value
                .as_ref()
                .unwrap()
                .string_value
                .as_deref(),
            Some("")
        );
        assert_eq!(
            decoded.record_field[2]
                .value
                .as_ref()
                .unwrap()
                .bytes_value
                .as_deref(),
            Some(&[0xff, 0, 0x80][..])
        );
    }

    #[test]
    fn duplicate_signed_value_hidden_by_prost_is_rejected() {
        let value = [number(1, 7), number(4, 9), number(4, 1)].concat();
        let record = record_with_value(&value);
        let decoded = Record::decode(record.as_slice()).unwrap();
        assert_eq!(
            decoded.record_field[0].value.as_ref().unwrap().signed_value,
            Some(1)
        );
        rejected(&success(&record));
    }

    #[test]
    fn unknown_value_tag_dropped_by_prost_is_rejected() {
        let clean = record_with_value(&[number(1, 7), number(4, 1)].concat());
        let dirty = record_with_value(&[number(1, 7), number(4, 1), number(99, 1)].concat());
        assert_eq!(
            Record::decode(clean.as_slice()).unwrap(),
            Record::decode(dirty.as_slice()).unwrap()
        );
        rejected(&success(&dirty));
    }

    #[test]
    fn duplicate_value_type_string_bytes_bool_and_date_are_rejected() {
        for value in [
            number(1, 7),
            number(4, 1),
            data(7, b"s"),
            data(2, b"opaque"),
            number(13, 1),
            data(6, &fixed(1, 1.0)),
            fixed(5, 1.0),
        ] {
            rejected(&success(&record_with_value(
                &[value.clone(), value].concat(),
            )));
        }
    }

    #[test]
    fn duplicate_record_retrieve_and_response_singulars_are_rejected() {
        let record = record_with_value(&number(4, 1));
        let retrieve = data(1, &record);
        let good = success(&record);
        for extra in [
            data(211, &retrieve),
            data(2, &operation()),
            data(3, &number(1, 1)),
        ] {
            rejected(&[good.clone(), extra].concat());
        }
        rejected(&frame(
            &operation(),
            &number(1, 1),
            Some(&[retrieve.clone(), retrieve].concat()),
        ));
        for singular in [
            data(1, b"etag"),
            data(2, &[]),
            data(3, &data(1, b"type")),
            data(4, &[]),
            data(5, &[]),
            data(8, &[]),
            data(9, &[]),
            data(11, b"device"),
            data(13, &[]),
            number(15, 0),
            data(22, &[]),
            data(24, b"pcs"),
        ] {
            rejected(&success(&[singular.clone(), singular].concat()));
        }
    }

    #[test]
    fn nested_identity_field_and_metadata_duplicates_and_unknowns_are_rejected() {
        for raw in [
            data(3, &[data(1, b"type"), data(1, b"type")].concat()),
            data(4, &[data(1, b"user"), number(31, 0)].concat()),
            data(2, &data(2, &[number(3, 1), number(3, 1)].concat())),
            data(7, &[data(1, &[]), data(1, &[])].concat()),
            data(7, &[data(2, &[]), data(2, &[])].concat()),
            data(
                7,
                &data(1, &[data(1, b"flags"), data(1, b"flags")].concat()),
            ),
            data(7, &data(1, &number(2, 0))),
            data(5, &data(1, &[fixed(1, 1.0), fixed(1, 2.0)].concat())),
            data(13, &[data(1, b"pcs"), data(1, b"pcs")].concat()),
            number(31, 0),
            data(16, &[]), // shareInfo is deliberately unsupported.
        ] {
            rejected(&success(&raw));
        }
    }

    #[test]
    fn order_nonminimal_varints_and_explicit_empty_are_preserved() {
        // etag key/length and permission value have valid nonminimal varints.
        let record = [0x8a, 0, 0x81, 0, b'e', 0x78, 0x81, 0];
        let framed = [
            data(211, &data(1, &record)),
            data(3, &number(1, 1)),
            data(2, &operation()),
            number(1, 0),
        ]
        .concat();
        assert_eq!(
            received_record_wire(&framed).unwrap(),
            Some(record.to_vec())
        );
        for value in [Vec::new(), data(7, b""), number(4, 0), data(2, b"")] {
            let record = record_with_value(&value);
            assert_eq!(
                received_record_wire(&success(&record)).unwrap(),
                Some(record)
            );
        }
    }

    #[test]
    fn ciphertext_is_not_scanned_as_encrypted_value_or_message_proto() {
        let opaque = [number(3, 1), number(3, 2), number(99, 5), vec![0xff]].concat();
        let record = record_with_value(&[number(1, 7), data(2, &opaque), number(13, 1)].concat());
        assert_eq!(
            received_record_wire(&success(&record)).unwrap(),
            Some(record)
        );
    }

    #[test]
    fn plain_error_frame_is_validated_before_returning_none() {
        let raw = frame(&operation(), &not_found(), None);
        assert!(received_record_wire(&raw).unwrap().is_none());
        let decoded = ResponseOperation::decode(raw.as_slice()).unwrap();
        assert_eq!(
            decoded
                .result
                .unwrap()
                .error
                .unwrap()
                .server_error
                .unwrap()
                .r#type,
            Some(3)
        );
        // Other explicit outcomes return no absence permission here.
        for code in [2, 3, 4] {
            assert!(
                received_record_wire(&frame(&operation(), &number(1, code), None))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn hidden_result_error_code_and_uuid_duplicates_never_return_none() {
        let op = operation();
        let raw = frame(&op, &not_found(), None);
        for extra in [data(3, &not_found()), data(2, &op)] {
            rejected(&[raw.clone(), extra].concat());
        }
        for result in [
            [number(1, 2), not_found()].concat(),
            [not_found(), data(2, &data(2, &number(1, 3)))].concat(),
            failure(&[data(2, &number(1, 2)), data(2, &number(1, 3))].concat()),
            failure(&data(2, &[number(1, 2), number(1, 3)].concat())),
        ] {
            let raw = frame(&op, &result, None);
            assert_eq!(
                ResponseOperation::decode(raw.as_slice())
                    .unwrap()
                    .result
                    .unwrap()
                    .error
                    .unwrap()
                    .server_error
                    .unwrap()
                    .r#type,
                Some(3)
            );
            rejected(&raw);
        }
        let duplicate_op = [data(1, b"other-request"), op].concat();
        let raw = frame(&duplicate_op, &not_found(), None);
        assert_eq!(
            ResponseOperation::decode(raw.as_slice())
                .unwrap()
                .response
                .unwrap()
                .operation_uuid
                .as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
        rejected(&raw);
    }

    #[test]
    fn unknown_error_identity_tags_and_missing_required_values_are_rejected() {
        for raw in [
            Vec::new(),
            data(3, &not_found()),
            frame(&[], &not_found(), None),
            frame(&data(1, b""), &not_found(), None),
            frame(&operation(), &[], None),
            frame(&operation(), &failure(&data(2, &[])), None),
            frame(&[operation(), number(31, 1)].concat(), &not_found(), None),
            frame(&operation(), &[not_found(), number(31, 1)].concat(), None),
            frame(
                &operation(),
                &failure(&[data(2, &number(1, 3)), number(31, 1)].concat()),
                None,
            ),
            frame(
                &operation(),
                &failure(&data(2, &[number(1, 3), number(31, 1)].concat())),
                None,
            ),
            [frame(&operation(), &not_found(), None), number(31, 1)].concat(),
        ] {
            rejected(&raw);
        }
    }

    #[test]
    fn contradictory_result_and_error_classes_cannot_become_not_found() {
        for code in [1, 2, 4] {
            let result = [number(1, code), data(2, &data(2, &number(1, 3)))].concat();
            rejected(&frame(&operation(), &result, None));
        }
        rejected(&frame(&operation(), &not_found(), Some(&data(1, &[]))));
        rejected(&frame(&operation(), &not_found(), Some(&[])));
        rejected(&frame(&operation(), &number(1, 1), None));
        let server = data(2, &number(1, 3));
        for other in [
            data(1, &number(1, 4)),
            data(7, &[data(1, b"extension"), number(2, 1)].concat()),
        ] {
            rejected(&frame(
                &operation(),
                &failure(&[server.clone(), other].concat()),
                None,
            ));
        }
    }

    #[test]
    fn widths_overflow_and_bool_aliases_are_rejected_before_prost_narrows() {
        let overflow = u64::from(u32::MAX) + 1;
        for value in [number(1, overflow + 7), number(13, 2)] {
            rejected(&success(&record_with_value(&value)));
        }
        rejected(&frame(&operation(), &number(1, overflow + 3), None));
        rejected(&frame(
            &operation(),
            &failure(&data(2, &number(1, overflow + 3))),
            None,
        ));
        rejected(&frame(
            &[data(1, b"id"), number(2, overflow + 211)].concat(),
            &not_found(),
            None,
        ));
        rejected(&frame(
            &operation(),
            &failure(&number(3, u64::from(u32::MAX))),
            None,
        ));
        // Correct sign-extended int32 remains valid, with no normalization.
        assert!(received_record_wire(&frame(
            &operation(),
            &failure(&number(3, (-1i64) as u64)),
            None
        ))
        .unwrap()
        .is_none());
    }

    #[test]
    fn wrong_wire_truncated_utf8_and_overflowing_lengths_are_rejected() {
        for value in [
            vec![0],
            vec![0x80],
            vec![0xff; 10],
            vec![0x08, 0x80],
            vec![0x0a, 0],
            vec![0x25, 0, 0, 0, 0], // type bytes / signed fixed32
            vec![0x29, 0],
            vec![0x3a, 2, b'x'],
            vec![0x3a, 1, 0xff],
            [vec![0x12], vi(u64::MAX)].concat(),
            [vec![0x20], vec![0xff; 9], vec![2]].concat(),
            vec![0x0b, 0x0c], // groups
        ] {
            rejected(&success(&record_with_value(&value)));
        }
        rejected(&[number(211, 0), data(2, &operation()), data(3, &not_found())].concat());
        rejected(&frame(&operation(), &number(1, 1), Some(&number(1, 0))));
        rejected(&frame(&number(1, 1), &not_found(), None));
    }

    #[test]
    fn repeated_lists_assets_and_nested_known_metadata_stay_bounded_and_exact() {
        let asset = [
            data(1, b"owner"),
            number(4, 3),
            data(12, b"raw"),
            data(15, &data(1, b"pcs")),
        ]
        .concat();
        let package = [data(1, &asset), data(2, &asset), data(2, &asset)].concat();
        let value = [
            data(11, &data(7, b"one")),
            data(11, &data(7, b"two")),
            data(8, &[fixed(1, 1.0), data(8, &fixed(1, 2.0))].concat()),
            data(
                9,
                &[number(1, 1), data(2, &data(1, &data(1, b"ref")))].concat(),
            ),
            data(10, &asset),
            data(12, &package),
        ]
        .concat();
        let record = record_with_value(&value);
        assert_eq!(
            received_record_wire(&success(&record)).unwrap(),
            Some(record)
        );
    }

    #[test]
    fn byte_field_and_depth_limits_fail_closed() {
        rejected(&vec![0; MAX_FRAME_BYTES + 1]);
        let many = data(11, &[]).repeat(MAX_FIELDS);
        rejected(&success(&record_with_value(&many)));
        let mut nested = Vec::new();
        for _ in 0..MAX_DEPTH {
            nested = data(11, &nested);
        }
        rejected(&success(&record_with_value(&nested)));
        let small = data(11, &data(11, &number(4, 0)));
        assert!(received_record_wire(&success(&record_with_value(&small))).is_ok());
    }

    #[test]
    fn record31_empty_metadata_preserves_original_record_and_typed_content() {
        let opaque = [number(1, 20), data(2, &[0xff, 0, 0x80]), number(13, 1)].concat();
        let base = [data(1, b"synthetic-etag"),
            data(2, &data(1, &data(1, b"synthetic-record"))),
            data(3, &data(1, b"MessageEncryptedV3")),
            data(7, &field("msgProto", &opaque)), data(24, &[0, 1, 2, 3])].concat();
        // Absent and present-empty remain different original wire values.
        // The current generated Record drops31; it must not replace raw bytes.
        let typed = Record::decode(base.as_slice()).unwrap();
        assert_eq!(received_record_wire(&success(&base)).unwrap(), Some(base.clone()));
        for record in [
            [data(31, &[]), base.clone()].concat(),
            [base.clone(), data(31, &[])].concat(),
            [base.clone(), vec![0xfa, 0x81, 0, 0x80, 0]].concat(),
        ] {
            let raw = received_record_wire(&success(&record)).unwrap().unwrap();
            assert_eq!(raw, record);
            assert_eq!(Record::decode(raw.as_slice()).unwrap(), typed);
            assert_ne!(raw, typed.encode_to_vec());
        }
    }

    #[test]
    fn record31_nonempty_protection_metadata_is_held_before_found() {
        let key = |kind| [data(1, b"synthetic-key"), number(2, kind)].concat();
        for metadata in [data(1, &[]), data(2, b""), data(2, b"synthetic-tag"),
            data(1, &data(1, b"")), data(1, &number(2, 1)),
            data(1, &key(1)), data(1, &key(2)), data(1, &key(3)),
            [data(1, &key(1)), data(1, &key(2)), data(2, b"synthetic-tag")].concat()] {
            let wire = success(&data(31, &metadata));
            assert!(matches!(received_record_wire(&wire), Err(PushError::BadMsg)));
            assert_eq!(received_record_wire_diagnostic(&wire).unwrap_err().to_string(),
                "schema=ProtectionKeysToRemove field=None reason=UnsupportedProtectionMetadata");
        }
    }

    #[test]
    fn record31_wrong_wire_truncation_nested_unknowns_and_duplicates_reject() {
        for (record, reason) in [(number(31, 0), "WrongWireType"),
            (fixed(31, 1.0), "WrongWireType"),
            ([vi((31 << 3) | 5), vec![0; 4]].concat(), "WrongWireType"),
            ([vi((31 << 3) | 2), vi(100), vec![0x42]].concat(), "InvalidLength"),
            ([vi((31 << 3) | 2), vec![0x80]].concat(), "InvalidLength"),
            ([data(31, &[]), data(31, &[])].concat(), "DuplicateSingular")] {
            let wire = success(&record);
            rejected(&wire);
            assert_eq!(received_record_wire_diagnostic(&wire).unwrap_err().to_string(),
                format!("schema=Record field=Some(31) reason={reason}"));
        }
        let key = [data(1, b"synthetic-key"), number(2, 1)].concat();
        for metadata in [number(1, 0), number(2, 0), data(2, &[0xff]),
            data(3, &[]), [data(2, b"a"), data(2, b"b")].concat(),
            data(1, &[data(1, b"a"), data(1, b"b")].concat()),
            data(1, &[number(2, 1), number(2, 1)].concat()),
            data(1, &number(1, 0)), data(1, &data(2, &[])),
            data(1, &data(3, &[])), data(1, &number(2, 0)),
            data(1, &number(2, 4)), data(1, &number(2, 0x1_0000_0001)),
            data(1, &number(2, u64::MAX)),
            data(1, &[vi((1 << 3) | 2), vi(100), vec![0x42]].concat()),
            [data(1, &key), data(2, &[0xff])].concat()] {
            let diagnostic = received_record_wire_diagnostic(&success(&data(31, &metadata)))
                .unwrap_err().to_string();
            assert!(!diagnostic.contains("UnsupportedProtectionMetadata"),
                "malformed content must be validated before the semantic hold");
        }
    }

    #[test]
    fn record31_does_not_relax_critical_duplicates_unknowns_or_bounds() {
        let empty = data(31, &[]);
        for record in [
            [empty.clone(), data(1, b"a"), data(1, b"b")].concat(),
            [empty.clone(), data(2, &[]), data(2, &[])].concat(),
            [empty.clone(), data(3, &[]), data(3, &[])].concat(),
            [empty.clone(), number(1, 0)].concat(),
            [empty.clone(), data(32, &[])].concat(),
            [empty.clone(), data(33, &[])].concat(),
            [empty.clone(), data(63, &[])].concat(),
        ] { rejected(&success(&record)); }
        // Inventory from the same pinned CKDPRecord decoder, not new support.
        // Protection/sharing/lifecycle families remain closed in this patch.
        for unsupported in [16, 17, 18, 21, 23, 26, 29, 30, 32, 33] {
            rejected(&success(&[empty.clone(), data(unsupported, &[])].concat()));
        }
        rejected(&success(&[empty.clone(), number(28, 0)].concat()));
        let duplicated_operation = [operation(), data(1, b"other-operation")].concat();
        rejected(&frame(&duplicated_operation, &number(1, 1), Some(&data(1, &empty))));
        rejected(&frame(&[], &number(1, 1), Some(&data(1, &empty))));
        rejected(&success(&data(31, &data(1, &[]).repeat(MAX_FIELDS))));
    }
}
