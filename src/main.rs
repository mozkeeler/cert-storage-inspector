extern crate base64;
extern crate curl;
extern crate lmdb;
extern crate rkv;
extern crate serde_json;

use curl::easy::Easy;
use lmdb::EnvironmentFlags;
use rkv::{Rkv, StoreOptions, Value};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::env;
use std::fmt::Display;
use std::path::PathBuf;

struct SimpleError {
    message: String,
}

impl<T: Display> From<T> for SimpleError {
    fn from(err: T) -> SimpleError {
        SimpleError {
            message: format!("{}", err),
        }
    }
}

fn main() {
    if let Err(e) = do_it() {
        eprintln!("{}", e.message);
    }
}

fn do_it() -> Result<(), SimpleError> {
    let current_revocations = download_current_revocations()?;
    let revocations_in_profile = read_profile_revocations()?;
    println!("revocations in OneCRL but not in profile:");
    for revocation in current_revocations.difference(&revocations_in_profile) {
        println!("{:?}", revocation);
    }
    println!("revocations in profile but not in OneCRL:");
    for revocation in revocations_in_profile.difference(&current_revocations) {
        println!("{:?}", revocation);
    }
    Ok(())
}

fn read_profile_revocations() -> Result<BTreeSet<Revocation>, SimpleError> {
    let db_path = env::args()
        .nth(1)
        .ok_or(SimpleError::from("expected path to cert_storage db"))?;
    let mut builder = Rkv::environment_builder();
    builder.set_max_dbs(2);
    builder.set_flags(EnvironmentFlags::READ_ONLY);
    let db_path = PathBuf::from(db_path);
    let env = Rkv::from_env(&db_path, builder)?;
    let store = env.open_single("cert_storage", StoreOptions::default())?;
    let reader = env.read()?;
    let iter = store.iter_start(&reader)?;
    let mut revocations: BTreeSet<Revocation> = BTreeSet::new();
    for item in iter {
        if let Ok((key, value)) = item {
            decode_item(key, &value, &mut revocations);
        }
    }
    Ok(revocations)
}

#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
enum RevocationType {
    IssuerSerial,
    SubjectPublicKey,
}

const PREFIX_REV_IS: &[u8] = b"is";
const PREFIX_REV_SPK: &[u8] = b"spk";

fn has_prefix(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() >= prefix.len() {
        return &data[..prefix.len()] == prefix;
    }
    false
}

fn decode_item(key: &[u8], value: &Option<Value>, revocations: &mut BTreeSet<Revocation>) {
    if has_prefix(key, PREFIX_REV_IS) {
        decode_revocation(
            &key[PREFIX_REV_IS.len()..],
            value,
            RevocationType::IssuerSerial,
            revocations,
        );
    }
}

fn split_der_key(key: &[u8]) -> Result<(&[u8], &[u8]), SimpleError> {
    if key.len() < 2 {
        return Err(SimpleError::from("key too short to be DER"));
    }
    let first_len_byte = key[1] as usize;
    if first_len_byte < 0x80 {
        if key.len() < first_len_byte + 2 {
            return Err(SimpleError::from("key too short"));
        }
        return Ok(key.split_at(first_len_byte + 2 as usize));
    }
    if first_len_byte == 0x80 {
        return Err(SimpleError::from("unsupported ASN.1"));
    }
    if first_len_byte == 0x81 {
        if key.len() < 3 {
            return Err(SimpleError::from("key too short to be DER"));
        }
        let len = key[2] as usize;
        if len < 0x80 {
            return Err(SimpleError::from("bad DER"));
        }
        if key.len() < len + 3 {
            return Err(SimpleError::from("key too short"));
        }
        return Ok(key.split_at(len + 3));
    }
    if first_len_byte == 0x82 {
        if key.len() < 4 {
            return Err(SimpleError::from("key too short to be DER"));
        }
        let len = (key[2] as usize) << 8 | key[3] as usize;
        if len < 256 {
            return Err(SimpleError::from("bad DER"));
        }
        if key.len() < len + 4 {
            return Err(SimpleError::from("key too short"));
        }
        return Ok(key.split_at(len + 4));
    }
    Err(SimpleError::from("key too long"))
}

fn decode_revocation(
    key: &[u8],
    value: &Option<Value>,
    typ: RevocationType,
    revocations: &mut BTreeSet<Revocation>,
) {
    match value {
        &Some(Value::I64(i)) if i == 1 => {}
        &Some(Value::I64(i)) if i == 0 => return,
        &None => return,
        &Some(_) => {
            eprintln!("unexpected value type for revocation entry");
            return;
        }
    }
    match split_der_key(key) {
        Ok((part1, part2)) => {
            if !revocations.insert(Revocation {
                typ,
                field1: base64::encode(part1),
                field2: base64::encode(part2),
            }) {
                eprintln!("duplicate entry in profile?");
            }
        }
        Err(e) => eprintln!("error decoding key: {}", e.message),
    }
}

#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
struct Revocation {
    typ: RevocationType,
    field1: String,
    field2: String,
}

fn download_current_revocations() -> Result<BTreeSet<Revocation>, SimpleError> {
    let mut easy = Easy::new();
    easy.url("https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records")?; // TODO: make configurable?
    let mut data = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    let records: JsonValue = serde_json::from_slice(&data)?;
    let records = records
        .as_object()
        .ok_or(SimpleError::from("unexpected type"))?;
    let data = records
        .get("data")
        .ok_or(SimpleError::from("missing data key"))?;
    let data = data
        .as_array()
        .ok_or(SimpleError::from("unexpected type"))?;
    let mut revocations: BTreeSet<Revocation> = BTreeSet::new();
    for entry in data {
        let entry = entry
            .as_object()
            .ok_or(SimpleError::from("unexpected type"))?;
        if entry.contains_key("issuerName") && entry.contains_key("serialNumber") {
            let issuer = entry
                .get("issuerName")
                .ok_or(SimpleError::from("couldn't get issuerName"))?;
            let issuer = issuer
                .as_str()
                .ok_or(SimpleError::from("issuerName not a string"))?;
            let serial = entry
                .get("serialNumber")
                .ok_or(SimpleError::from("couldn't get serialNumber"))?;
            let serial = serial
                .as_str()
                .ok_or(SimpleError::from("serialNumber not a string"))?;
            if !revocations.insert(Revocation {
                typ: RevocationType::IssuerSerial,
                field1: issuer.to_owned(),
                field2: serial.to_owned(),
            }) {
                eprintln!("duplicate entry in OneCRL?");
            }
        } else if entry.contains_key("subject") && entry.contains_key("pubKeyHash") {
            // TODO: I'm not actually sure about these field names, because there aren't any
            // examples of them in the current data set.
            let subject = entry
                .get("subject")
                .ok_or(SimpleError::from("couldn't get subject"))?;
            let subject = subject
                .as_str()
                .ok_or(SimpleError::from("subject not a string"))?;
            let pub_key_hash = entry
                .get("pubKeyHash")
                .ok_or(SimpleError::from("couldn't get pubKeyHash"))?;
            let pub_key_hash = pub_key_hash
                .as_str()
                .ok_or(SimpleError::from("pubKeyHash not a string"))?;
            if !revocations.insert(Revocation {
                typ: RevocationType::IssuerSerial,
                field1: subject.to_owned(),
                field2: pub_key_hash.to_owned(),
            }) {
                eprintln!("duplicate entry?");
            }
        } else {
            eprintln!("entry with no issuer/serial or no subject/pubKeyHash");
        }
    }
    Ok(revocations)
}
