use std::{
    collections::BTreeMap,
    ffi::CStr,
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    ptr,
    str::FromStr,
    sync::Mutex,
};

use crate::{
    dnsdist::{DNSQuestion, Packet},
    domain::DomainMatcher,
    ip::IpMatcher,
};
mod dnsdist;
mod domain;
mod ip;

static LOADED_GEOSITE: Mutex<BTreeMap<PathBuf, &'static DomainMatcher>> =
    Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruder_load_site_rule(path: *const i8) -> *const DomainMatcher {
    let path = unsafe {
        PathBuf::from_str(str::from_utf8(CStr::from_ptr(path).to_bytes()).unwrap()).unwrap()
    };
    let mut cache = LOADED_GEOSITE.lock().unwrap();
    if let Some(r) = cache.get(&path) {
        return ptr::from_ref(*r);
    }
    let Ok(file) = File::options()
        .read(true)
        .create(false)
        .write(false)
        .open(&path)
        .inspect_err(|err| {
            eprintln!(
                "File {} cannot be open with error {err}",
                path.as_os_str().to_str().unwrap_or("?")
            );
        })
    else {
        return ptr::null();
    };
    let Ok(r) = DomainMatcher::from_reader(BufReader::new(file)).inspect_err(|err| {
        eprintln!(
            "File {} cannot be parse with error {err}",
            path.as_os_str().to_str().unwrap_or("?")
        );
    }) else {
        return ptr::null();
    };
    let r = Box::leak(Box::new(r));
    cache.insert(path, r);
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruder_match_query_for_site_rule(
    q: DNSQuestion,
    rule: *const DomainMatcher,
) -> bool {
    let rule: &'static _ = unsafe { &*rule };
    rule.match_domain(&q.get_qname_full())
}

static LOADED_IP: Mutex<BTreeMap<PathBuf, &'static IpMatcher>> = Mutex::new(BTreeMap::new());

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruder_load_ip_rule(path: *const i8) -> *const IpMatcher {
    let path = unsafe {
        PathBuf::from_str(str::from_utf8(CStr::from_ptr(path).to_bytes()).unwrap()).unwrap()
    };
    let mut cache = LOADED_IP.lock().unwrap();
    if let Some(r) = cache.get(&path) {
        return ptr::from_ref(*r);
    }
    let Ok(file) = File::options()
        .read(true)
        .create(false)
        .write(false)
        .open(&path)
        .inspect_err(|err| {
            eprintln!(
                "File {} cannot be open with error {err}",
                path.as_os_str().to_str().unwrap_or("?")
            );
        })
    else {
        return ptr::null();
    };
    let Ok(r) = IpMatcher::from_reader(BufReader::new(file)).inspect_err(|err| {
        eprintln!(
            "File {} cannot be parse with error {err}",
            path.as_os_str().to_str().unwrap_or("?")
        );
    }) else {
        return ptr::null();
    };
    let r = Box::leak(Box::new(r));
    cache.insert(path, r);
    r
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruder_match_query_for_ip_rule(
    q: DNSQuestion,
    rule: *const IpMatcher,
    _invert: bool,
) -> bool {
    let rule: &'static _ = unsafe { &*rule };
    let pack = Packet::new(q);
    pack.records()
        .find(|r| r.as_ip().is_some_and(|ip| rule.matches(ip)))
        .is_some()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn my_dnsdist_ffi_action(q: DNSQuestion) {
    eprintln!("Query = {}", q.get_qname_full());
    let pack = Packet::new(q);
    for record in pack.records() {
        let buf = record.content();
        let value = match record.record_type() {
            dnsdist::QType::A => {
                format_args!("{}", Ipv4Addr::from_octets(*buf.as_array().unwrap()))
            }
            dnsdist::QType::AAAA => {
                format_args!("{}", Ipv6Addr::from_octets(*buf.as_array().unwrap()))
            }
            dnsdist::QType::CNAME => {
                format_args!("{:?}", record.as_cname())
            }
            _ => format_args!("?"),
        };
        eprintln!(
            "Record = type({:?}) ttl({}) value = {}",
            record.record_type(),
            record.ttl(),
            value
        );
    }
}
