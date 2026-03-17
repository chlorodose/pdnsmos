mod ffi {
    #![allow(
        unused,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        clippy::unreadable_literal
    )]
    pub const SELECTION_QUESTION: u8 = 0;
    pub const SELECTION_ANSWER: u8 = 1;
    pub const SELECTION_AUTHORITY: u8 = 2;
    pub const SELECTION_ADDITIONAL: u8 = 3;
    std::include!("./dnsdist_lua_ffi_interface.rs");
}
use std::{
    mem::transmute,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::{self, NonNull},
    slice, str,
};

#[allow(clippy::wildcard_imports)]
use ffi::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    ENT = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    RKEY = 57,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    HHIT = 67,
    BRID = 68,
    SPF = 99,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
    URI = 256,
    CAA = 257,
    RESINFO = 261,
    DLV = 32769,
    ADDR = 65400,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct DNSQuestion {
    inner: *mut ffi::dnsdist_ffi_dnsquestion_t,
}
impl DNSQuestion {
    pub fn get_qname_full(&self) -> String {
        let mut ptr = ptr::null();
        let mut len = 0;
        unsafe { dnsdist_ffi_dnsquestion_get_qname_raw(self.inner, &raw mut ptr, &raw mut len) };
        let mut vec = Vec::new();
        vec.extend_from_slice(unsafe { slice::from_raw_parts(ptr.cast(), len) });
        let mut idx = 0;
        while vec[idx] != 0 {
            let tmp = vec[idx];
            vec[idx] = b'.';
            idx += tmp as usize + 1;
        }
        assert_eq!(idx, len - 1);
        assert_eq!(vec.pop(), Some(b'\0'));
        unsafe { String::from_utf8_unchecked(vec) }
    }
}

#[derive(Debug)]
pub struct Packet {
    ptr: NonNull<dnsdist_ffi_dnspacket_t>,
    base: *const u8,
    len: usize,
}
impl Drop for Packet {
    fn drop(&mut self) {
        unsafe { dnsdist_ffi_dnspacket_free(self.ptr.as_ptr()) };
    }
}
impl Packet {
    /// Create a new Packet from a DNSQuestion
    pub fn new(q: DNSQuestion) -> Self {
        unsafe {
            let header = dnsdist_ffi_dnsquestion_get_header(q.inner);
            let len = dnsdist_ffi_dnsquestion_get_len(q.inner);

            let mut pack = ptr::null_mut();
            assert!(dnsdist_ffi_dnspacket_parse(
                header.cast(),
                len as usize,
                &raw mut pack
            ));
            Self {
                ptr: NonNull::new(pack).unwrap(),
                base: header.cast(),
                len: len as usize,
            }
        }
    }

    /// Get the question type (QTYPE)
    pub fn get_qtype(&self) -> QType {
        unsafe { transmute(dnsdist_ffi_dnspacket_get_qtype(self.ptr.as_ptr())) }
    }

    /// Get the question class (QCLASS)
    pub fn get_qclass(&self) -> u16 {
        unsafe { dnsdist_ffi_dnspacket_get_qclass(self.ptr.as_ptr()) }
    }

    /// Get the number of records in a specific section
    /// section: 0=Question, 1=Answer, 2=Authority, 3=Additional
    pub fn get_records_count(&self, section: u8) -> u16 {
        unsafe { dnsdist_ffi_dnspacket_get_records_count_in_section(self.ptr.as_ptr(), section) }
    }

    /// Get the total number of records in all sections
    pub fn get_total_records(&self) -> u16 {
        self.get_records_count(SELECTION_QUESTION)
            + self.get_records_count(SELECTION_ANSWER)
            + self.get_records_count(SELECTION_AUTHORITY)
            + self.get_records_count(SELECTION_ADDITIONAL)
    }

    /// Get a record's name as raw bytes at the given index
    pub fn get_record_name_raw(&self, idx: usize) -> &[u8] {
        unsafe {
            let mut name = ptr::null();
            let mut name_size = 0;
            dnsdist_ffi_dnspacket_get_record_name_raw(
                self.ptr.as_ptr(),
                idx,
                &raw mut name,
                &raw mut name_size,
            );
            std::slice::from_raw_parts(name.cast(), name_size)
        }
    }

    /// Get a record's type at the given index
    pub fn get_record_type(&self, idx: usize) -> QType {
        unsafe {
            transmute(dnsdist_ffi_dnspacket_get_record_type(
                self.ptr.as_ptr(),
                idx,
            ))
        }
    }

    /// Get a record's TTL at the given index
    pub fn get_record_ttl(&self, idx: usize) -> u32 {
        unsafe { dnsdist_ffi_dnspacket_get_record_ttl(self.ptr.as_ptr(), idx) }
    }

    /// Get a record's content length at the given index
    pub fn get_record_content(&self, idx: usize) -> &[u8] {
        let len =
            unsafe { dnsdist_ffi_dnspacket_get_record_content_length(self.ptr.as_ptr(), idx) };
        let offset =
            unsafe { dnsdist_ffi_dnspacket_get_record_content_offset(self.ptr.as_ptr(), idx) };
        unsafe { slice::from_raw_parts(self.base.add(offset as usize), len as usize) }
    }

    pub fn get_record_name(&self, idx: usize) -> &str {
        let mut ptr = ptr::null();
        let mut len = 0;
        unsafe {
            dnsdist_ffi_dnspacket_get_record_name_raw(
                self.ptr.as_ptr(),
                idx,
                &raw mut ptr,
                &raw mut len,
            );
            str::from_utf8_unchecked(slice::from_raw_parts(ptr.cast(), len))
        }
    }

    pub fn parse_cname_record(&self, idx: usize) -> String {
        let _len =
            unsafe { dnsdist_ffi_dnspacket_get_record_content_length(self.ptr.as_ptr(), idx) };
        let offset =
            unsafe { dnsdist_ffi_dnspacket_get_record_content_offset(self.ptr.as_ptr(), idx) };
        let mut buf = [0u8; 256];
        let len = unsafe {
            dnsdist_ffi_dnspacket_get_name_at_offset_raw(
                self.base.cast(),
                self.len,
                offset as usize,
                buf.as_mut_ptr().cast(),
                255,
            )
        };
        let mut idx = 0;
        while buf[idx] != 0 {
            let tmp = buf[idx];
            buf[idx] = b'.';
            idx += tmp as usize + 1;
        }
        assert_eq!(idx, len - 1);
        str::from_utf8(&buf[0..idx]).unwrap().to_string()
    }

    /// Iterator over all records in the packet
    pub fn records(&self) -> RecordIterator<'_> {
        RecordIterator {
            packet: self,
            current: 0,
            total: self.get_total_records(),
        }
    }
}

/// Iterator over DNS records
pub struct RecordIterator<'a> {
    packet: &'a Packet,
    current: usize,
    total: u16,
}

impl<'a> Iterator for RecordIterator<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.total as usize {
            let record = Record {
                packet: self.packet,
                index: self.current,
            };
            self.current += 1;
            Some(record)
        } else {
            None
        }
    }
}

/// Represents a single DNS record
#[derive(Debug)]
pub struct Record<'a> {
    packet: &'a Packet,
    index: usize,
}

impl<'a> Record<'a> {
    /// Get the record name as raw bytes
    pub fn name_raw(&self) -> &[u8] {
        self.packet.get_record_name_raw(self.index)
    }

    /// Get the record type
    pub fn record_type(&self) -> QType {
        self.packet.get_record_type(self.index)
    }

    /// Get the record TTL
    pub fn ttl(&self) -> u32 {
        self.packet.get_record_ttl(self.index)
    }

    pub fn content(&self) -> &[u8] {
        self.packet.get_record_content(self.index)
    }

    pub fn record_name(&self) -> &str {
        self.packet.get_record_name(self.index)
    }

    pub fn as_cname(&self) -> Option<String> {
        if self.record_type() != QType::CNAME {
            return None;
        }
        Some(self.packet.parse_cname_record(self.index))
    }

    pub fn as_ip(&self) -> Option<IpAddr> {
        Some(match self.record_type() {
            QType::A => IpAddr::V4(Ipv4Addr::from_octets(*self.content().as_array().unwrap())),
            QType::AAAA => IpAddr::V6(Ipv6Addr::from_octets(*self.content().as_array().unwrap())),
            _ => return None,
        })
    }
}
