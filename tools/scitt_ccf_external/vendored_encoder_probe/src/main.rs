//! ccf::cose::edit::set_unprotected_header(input, desc::Empty{}) of CCF ccf-7.0.17
//! (src/crypto/cose.cpp lines 18-89), transcribed call for call onto the C ABI that CCF's C++ wrapper
//! tav::cbor (3rdparty/internal/tee-attestation-verification/ffi/include/tav/cbor.hpp) calls. The ABI is
//! CCF's vendored copy of tee-attestation-verification-ffi 1.0.8, linked as a crate, over EverCBOR.
//!
//! This file is ours; the functions it calls are not. stdin: one "<id> <hex>" per line.
//! stdout: "<id> OK <hex of the serialized bytes>" or "<id> ERR <step> <status> <message>".
use std::io::BufRead;

extern crate tee_attestation_verification_ffi; // defines the tav_cbor_* symbols below

#[repr(C)]
struct TavCborHandle {
    _opaque: [u8; 0],
}

extern "C" {
    fn tav_cbor_nondet_parse(data: *const u8, len: usize, max_depth: usize, out: *mut *mut TavCborHandle,
                             err_ptr: *mut *mut u8, err_len: *mut usize) -> i32;
    fn tav_cbor_tag_at(value: *const TavCborHandle, tag: u64, out: *mut *mut TavCborHandle) -> i32;
    fn tav_cbor_array_at(value: *const TavCborHandle, index: usize, out: *mut *mut TavCborHandle) -> i32;
    fn tav_cbor_shallow_copy(value: *const TavCborHandle) -> *mut TavCborHandle;
    fn tav_cbor_make_map(pairs: *mut *mut TavCborHandle, pair_count: usize) -> *mut TavCborHandle;
    fn tav_cbor_make_array(items: *mut *mut TavCborHandle, count: usize) -> *mut TavCborHandle;
    fn tav_cbor_make_tagged(tag: u64, payload: *mut *mut TavCborHandle) -> *mut TavCborHandle;
    fn tav_cbor_nondet_serialize(value: *const TavCborHandle, max_depth: usize, out_ptr: *mut *mut u8,
                                 out_len: *mut usize, err_ptr: *mut *mut u8, err_len: *mut usize) -> i32;
    fn tav_cbor_free(value: *mut TavCborHandle);
    fn tav_cbor_buffer_free(ptr: *mut u8, len: usize);
}

/// TAV_CBOR_MAX_DEPTH, ffi/include/tav/internal/cbor_abi.h line 57; cbor.hpp's default max_depth.
const MAX_DEPTH: usize = 256;
/// ccf::cbor::tag::COSE_SIGN_1, src/crypto/cbor_tags.h line 14.
const COSE_SIGN_1: u64 = 18;

unsafe fn take_message(ptr: *mut u8, len: usize) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).replace('\n', " ");
    tav_cbor_buffer_free(ptr, len);
    s
}

/// The steps of cose.cpp lines 23-40 and 42-48, 83-88, in that order. Handles are released as the
/// C++ destructors would release them; the input buffer outlives every borrowing handle.
unsafe fn edit(input: &[u8]) -> Result<Vec<u8>, String> {
    let (mut err, mut err_len) = (std::ptr::null_mut(), 0usize);
    let mut cose_cbor = std::ptr::null_mut();
    let st = tav_cbor_nondet_parse(input.as_ptr(), input.len(), MAX_DEPTH, &mut cose_cbor, &mut err, &mut err_len);
    if st != 0 {
        return Err(format!("nondet_parse {} {}", st, take_message(err, err_len)));
    }
    let mut envelope = std::ptr::null_mut();
    let st = tav_cbor_tag_at(cose_cbor, COSE_SIGN_1, &mut envelope);
    if st != 0 {
        tav_cbor_free(cose_cbor);
        return Err(format!("tag_at {} Failed to parse COSE_Sign1 tag", st));
    }
    let mut parts = [std::ptr::null_mut(); 3];
    for (slot, index) in parts.iter_mut().zip([0usize, 2, 3]) {
        let st = tav_cbor_array_at(envelope, index, slot);
        if st != 0 {
            for h in parts {
                tav_cbor_free(h);
            }
            tav_cbor_free(envelope);
            tav_cbor_free(cose_cbor);
            return Err(format!("array_at({}) {} element missing", index, st));
        }
    }
    // edited = [shallow_copy(phdr), make_map({}), shallow_copy(payload), shallow_copy(signature)]
    let mut edited = [
        tav_cbor_shallow_copy(parts[0]),
        tav_cbor_make_map(std::ptr::null_mut(), 0),
        tav_cbor_shallow_copy(parts[1]),
        tav_cbor_shallow_copy(parts[2]),
    ];
    let mut array = tav_cbor_make_array(edited.as_mut_ptr(), edited.len());
    let tagged = tav_cbor_make_tagged(COSE_SIGN_1, &mut array);
    let (mut out, mut out_len) = (std::ptr::null_mut(), 0usize);
    let st = tav_cbor_nondet_serialize(tagged, MAX_DEPTH, &mut out, &mut out_len, &mut err, &mut err_len);
    let result = if st != 0 {
        Err(format!("nondet_serialize {} {}", st, take_message(err, err_len)))
    } else {
        let bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        tav_cbor_buffer_free(out, out_len);
        Ok(bytes)
    };
    tav_cbor_free(tagged);
    for h in parts {
        tav_cbor_free(h);
    }
    tav_cbor_free(envelope);
    tav_cbor_free(cose_cbor);
    result
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn main() {
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let mut it = line.split_whitespace();
        let (Some(id), Some(hx)) = (it.next(), it.next()) else { continue };
        let Some(input) = unhex(hx) else {
            println!("{} ERR input 0 not hex", id);
            continue;
        };
        match unsafe { edit(&input) } {
            Ok(b) => println!("{} OK {}", id, b.iter().map(|x| format!("{:02x}", x)).collect::<String>()),
            Err(e) => println!("{} ERR {}", id, e),
        }
    }
}
