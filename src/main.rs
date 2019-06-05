extern crate base64;
extern crate byteorder;
#[macro_use]
extern crate clap;
extern crate curl;
extern crate lmdb;
extern crate rkv;
extern crate serde_json;
extern crate sha2;

use byteorder::{NetworkEndian, ReadBytesExt};
use clap::App;
use curl::easy::Easy;
use lmdb::EnvironmentFlags;
use rkv::{Rkv, StoreOptions, Value};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Display;
use std::mem::size_of;
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

const CERT_SERIALIZATION_VERSION_1: u8 = 1;
const DEFAULT_ONECRL_URL: &str = "https://firefox.settings.services.mozilla.com/v1/\
                                  buckets/security-state/collections/onecrl/records";
const DEFAULT_CRLITE_URL: &str = "https://settings.stage.mozaws.net/v1/\
                                  buckets/security-state/collections/intermediates/records";

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();
    let onecrl_url = matches.value_of("onecrl-url").unwrap_or(DEFAULT_ONECRL_URL);
    let crlite_url = matches.value_of("crlite-url").unwrap_or(DEFAULT_CRLITE_URL);
    let profile_path = matches
        .value_of("profile-path")
        .expect("need path to Firefox profile");
    if let Err(e) = do_it(onecrl_url, crlite_url, profile_path) {
        eprintln!("{}", e.message);
    }
}

fn do_it(onecrl_url: &str, crlite_url: &str, profile_path: &str) -> Result<(), SimpleError> {
    //let current_revocations = download_current_revocations(onecrl_url)?;
    //println!("current OneCRL revocations: {}", current_revocations.len());
    //let revocations_in_profile = read_profile_revocations(profile_path)?;
    //println!("revocations in profile: {}", revocations_in_profile.len());
    //println!("revocations in OneCRL but not in profile:");
    /*
    for revocation in current_revocations.difference(&revocations_in_profile) {
        println!("{:?}", revocation);
    }
    println!("revocations in profile but not in OneCRL:");
    for revocation in revocations_in_profile.difference(&current_revocations) {
        println!("{:?}", revocation);
    }
    */
    let crlite_certs = download_current_certificates(crlite_url)?;
    let profile_certs_list = read_profile_certificates(profile_path)?;
    let mut profile_certs = BTreeSet::new();
    for cert in profile_certs_list {
        let cert_for_comparison = PreloadedCert::from(&cert);
        if profile_certs.contains(&cert_for_comparison) {
            eprintln!("duplicate preloaded certificate in profile?");
        }
        profile_certs.insert(cert_for_comparison);
        validate_cert(profile_path, &cert)?;
    }
    let certs_not_in_profile = crlite_certs.difference(&profile_certs);
    println!(
        "{} certs in CRLite but not profile",
        certs_not_in_profile.count()
    );
    /*
    println!("preloaded certificates in CRLite but not profile:");
    for cert in  certs_not_in_profile {
        println!("{}", base64::encode(&cert.subject));
    }
    */
    /*
    println!("preloaded certificates in profile but not CRLite:");
    for cert in certs_for_comparison.difference(&crlite_certs) {
        println!("{}", base64::encode(&cert.subject));
    }
    */
    Ok(())
}

fn download_current_certificates(
    cert_preloads_url: &str,
) -> Result<BTreeSet<PreloadedCert>, SimpleError> {
    // TODO: this prerlude bit can be refactored
    let mut easy = Easy::new();
    easy.url(cert_preloads_url)?;
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
    let mut preloaded_certs = BTreeSet::new();
    for entry in data {
        let entry = entry
            .as_object()
            .ok_or(SimpleError::from("unexpected type"))?;
        let der_hash = entry.get("derHash").ok_or(SimpleError::from(format!(
            "couldn't get derHash: {:?}",
            entry
        )))?;
        let der_hash = der_hash
            .as_str()
            .ok_or(SimpleError::from("derHash not a string"))?;
        let subject_dn = entry.get("subjectDN").ok_or(SimpleError::from(format!(
            "couldn't get subjectDN: {:?}",
            entry
        )))?;
        let subject_dn = subject_dn
            .as_str()
            .ok_or(SimpleError::from("subjectDN not string"))?;
        let preloaded_cert = PreloadedCert {
            der_hash: base64::decode_config(der_hash, base64::URL_SAFE)?,
            subject: base64::decode_config(subject_dn, base64::URL_SAFE)?,
        };
        if preloaded_certs.contains(&preloaded_cert) {
            eprintln!("duplicate preloaded certificate in CRLite?");
        }
        preloaded_certs.insert(preloaded_cert);
    }
    Ok(preloaded_certs)
}

#[derive(Ord, Eq, PartialOrd, PartialEq, Debug)]
struct PreloadedCert {
    der_hash: Vec<u8>,
    subject: Vec<u8>,
}

impl PreloadedCert {
    fn from(cert: &Cert) -> PreloadedCert {
        PreloadedCert {
            der_hash: Sha256::digest(&cert.der).to_vec(),
            subject: cert.subject.clone(),
        }
    }
}

fn read_profile_certificates(profile_path: &str) -> Result<Vec<Cert>, SimpleError> {
    let mut builder = Rkv::environment_builder();
    builder.set_max_dbs(2);
    builder.set_flags(EnvironmentFlags::READ_ONLY);
    let mut db_path = PathBuf::from(profile_path);
    db_path.push("security_state");
    let env = Rkv::from_env(&db_path, builder)?;
    let store = env.open_single("cert_storage", StoreOptions::default())?;
    let reader = env.read()?;
    let iter = store.iter_start(&reader)?;
    let mut certs = Vec::new();
    for item in iter {
        if let Ok((key, value)) = item {
            maybe_decode_certificate(key, &value, &mut certs);
        }
    }
    Ok(certs)
}

fn maybe_decode_certificate(key: &[u8], value: &Option<Value>, certs: &mut Vec<Cert>) {
    if !has_prefix(key, PREFIX_CERT) {
        return;
    }
    if let Some(Value::Blob(bytes)) = value {
        if let Ok(cert) = Cert::from_bytes(bytes) {
            let cert_hash = Sha256::digest(&cert.der);
            if &key[PREFIX_CERT.len()..] != cert_hash.as_slice() {
                eprintln!("cert identified by key does not match hash"); // TODO
            }
            certs.push(cert);
        }
    }
}

struct Cert {
    der: Vec<u8>,
    subject: Vec<u8>,
    trust: i16,
}

impl Cert {
    fn from_bytes(encoded: &[u8]) -> Result<Cert, SimpleError> {
        if encoded.len() < size_of::<u8>() {
            return Err(SimpleError::from("invalid Cert: no version?"));
        }
        let (mut version, rest) = encoded.split_at(size_of::<u8>());
        let version = version.read_u8()?;
        if version != CERT_SERIALIZATION_VERSION_1 {
            return Err(SimpleError::from("invalid Cert: unexpected version"));
        }

        if rest.len() < size_of::<u16>() {
            return Err(SimpleError::from("invalid Cert: no der len?"));
        }
        let (mut der_len, rest) = rest.split_at(size_of::<u16>());
        let der_len = der_len.read_u16::<NetworkEndian>()? as usize;
        if rest.len() < der_len {
            return Err(SimpleError::from("invalid Cert: no der?"));
        }
        let (der, rest) = rest.split_at(der_len);

        if rest.len() < size_of::<u16>() {
            return Err(SimpleError::from("invalid Cert: no subject len?"));
        }
        let (mut subject_len, rest) = rest.split_at(size_of::<u16>());
        let subject_len = subject_len.read_u16::<NetworkEndian>()? as usize;
        if rest.len() < subject_len {
            return Err(SimpleError::from("invalid Cert: no subject?"));
        }
        let (subject, mut rest) = rest.split_at(subject_len);

        if rest.len() < size_of::<i16>() {
            return Err(SimpleError::from("invalid Cert: no trust?"));
        }
        let trust = rest.read_i16::<NetworkEndian>()?;
        if rest.len() > 0 {
            return Err(SimpleError::from("invalid Cert: trailing data?"));
        }

        Ok(Cert {
            der: der.to_owned(),
            subject: subject.to_owned(),
            trust,
        })
    }
}

fn make_key(prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_owned();
    key.extend_from_slice(bytes);
    key
}

fn validate_cert(profile_path: &str, cert: &Cert) -> Result<(), SimpleError> {
    // TODO: a lot of this can be refactored...
    let mut builder = Rkv::environment_builder();
    builder.set_max_dbs(2);
    builder.set_flags(EnvironmentFlags::READ_ONLY);
    let mut db_path = PathBuf::from(profile_path);
    db_path.push("security_state");
    let env = Rkv::from_env(&db_path, builder)?;
    let store = env.open_single("cert_storage", StoreOptions::default())?;
    let reader = env.read()?;
    let subject_key = make_key(PREFIX_SUBJECT, &cert.subject);
    let hash_list = match store.get(&reader, subject_key)? {
        Some(Value::Blob(b)) => b.to_owned(),
        Some(_) => {
            return Err(SimpleError::from(
                "unexpected value when looking up subject",
            ))
        }
        None => return Err(SimpleError::from("no value when looking up subject")),
    };
    if hash_list.len() % Sha256::output_size() != 0 {
        return Err(SimpleError::from("unexpected hash list size"));
    }
    let cert_hash = Sha256::digest(&cert.der);
    let mut found = false;
    for hash in hash_list.chunks_exact(Sha256::output_size()) {
        if hash == cert_hash.as_slice() {
            found = true;
        }
    }
    if !found {
        return Err(SimpleError::from("cert hash not in hash list"));
    }
    // TODO: lookup trust?
    Ok(())
}

fn read_profile_revocations(profile_path: &str) -> Result<BTreeSet<Revocation>, SimpleError> {
    let mut builder = Rkv::environment_builder();
    builder.set_max_dbs(2);
    builder.set_flags(EnvironmentFlags::READ_ONLY);
    let mut db_path = PathBuf::from(profile_path);
    db_path.push("security_state");
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
const PREFIX_CERT: &[u8] = b"cert";
const PREFIX_SUBJECT: &[u8] = b"subject";

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
    } else if has_prefix(key, PREFIX_REV_SPK) {
        decode_revocation(
            &key[PREFIX_REV_SPK.len()..],
            value,
            RevocationType::SubjectPublicKey,
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
            let revocation = Revocation {
                typ,
                field1: base64::encode(part1),
                field2: base64::encode(part2),
            };
            if revocations.contains(&revocation) {
                eprintln!("duplicate entry in profile? ({:?})", revocation);
            } else {
                revocations.insert(revocation);
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

fn download_current_revocations(onecrl_url: &str) -> Result<BTreeSet<Revocation>, SimpleError> {
    let mut easy = Easy::new();
    easy.url(onecrl_url)?;
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
        let revocation = if entry.contains_key("issuerName") && entry.contains_key("serialNumber") {
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
            Revocation {
                typ: RevocationType::IssuerSerial,
                field1: issuer.to_owned(),
                field2: serial.to_owned(),
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
            Revocation {
                typ: RevocationType::SubjectPublicKey,
                field1: subject.to_owned(),
                field2: pub_key_hash.to_owned(),
            }
        } else {
            eprintln!("entry with no issuer/serial or no subject/pubKeyHash");
            continue;
        };
        if revocations.contains(&revocation) {
            eprintln!("duplicate entry in OneCRL? ({:?})", revocation);
        } else {
            revocations.insert(revocation);
        }
    }
    Ok(revocations)
}
