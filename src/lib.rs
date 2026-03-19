use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    ptr,
    str::FromStr,
    sync::Mutex,
};

use crate::{
    dnsdist::{DNSQuestion, Packet},
    domain::DomainMatcher,
    ip::IpMatcher,
    nftset::NftTarget,
};
mod dnsdist;
mod domain;
mod ip;
mod nftset;

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
pub unsafe extern "C" fn ruder_load_nftset_target(expr: *const i8) -> *mut NftTarget {
    unsafe {
        let s = CStr::from_ptr(expr).to_str().unwrap();
        let Ok(target) =
            NftTarget::new(s).inspect_err(|err| eprintln!("Failed to parse nftset expr {err}"))
        else {
            return ptr::null_mut();
        };
        Box::into_raw(Box::new(target))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ruder_commit_to_nftset(
    q: DNSQuestion,
    target: *mut NftTarget,
    reconnect: bool,
) -> bool {
    let target: &'static mut NftTarget = unsafe { &mut *target };
    if reconnect {
        if target
            .reconnect()
            .inspect_err(|err| eprintln!("Failed to connect to nftsetd: {err}"))
            .is_err()
        {
            return true;
        }
    }
    let name = &q.get_qname_full()[1..];
    let pack = Packet::new(q);
    let addrs = pack.records().filter_map(|record| {
        let buf = record.content();
        Some(match record.record_type() {
            dnsdist::QType::A => IpAddr::from(Ipv4Addr::from_octets(*buf.as_array().unwrap())),
            dnsdist::QType::AAAA => IpAddr::from(Ipv6Addr::from_octets(*buf.as_array().unwrap())),
            _ => return None,
        })
    });
    target
        .run(addrs, name)
        .inspect_err(|err| eprintln!("Failed to commit to nftset: {err}"))
        .is_err()
}
