//! Example native AresBird plugin (cdylib).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use serde_json::json;

#[no_mangle]
pub extern "C" fn ares_plugin_api_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn ares_plugin_name() -> *const c_char {
    static NAME: &[u8] = b"native-hello\0";
    NAME.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ares_plugin_description() -> *const c_char {
    static DESC: &[u8] = b"Example native AresBird plugin (ABI v1)\0";
    DESC.as_ptr() as *const c_char
}

#[no_mangle]
pub unsafe extern "C" fn ares_plugin_run(req_json: *const c_char) -> *mut c_char {
    if req_json.is_null() {
        return respond_err("null request");
    }
    let req = match CStr::from_ptr(req_json).to_str() {
        Ok(s) => s,
        Err(_) => return respond_err("invalid utf8 request"),
    };

    let targets = serde_json::from_str::<serde_json::Value>(req)
        .ok()
        .and_then(|v| {
            v.get("targets").and_then(|t| t.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();

    let msg = format!(
        "native-hello says hi; targets={}",
        if targets.is_empty() {
            "(none)".into()
        } else {
            targets.join(",")
        }
    );

    let body = json!({
        "ok": true,
        "events": [
            {
                "type": "log",
                "level": "info",
                "message": msg
            },
            {
                "type": "probe_result",
                "addr": targets.first().and_then(|t| t.parse::<std::net::IpAddr>().ok()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                "port": 0,
                "probe": "native-hello",
                "detail": "example native plugin executed",
                "confidence": 1.0
            }
        ]
    });

    match CString::new(body.to_string()) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn ares_plugin_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

fn respond_err(msg: &str) -> *mut c_char {
    let body = json!({ "ok": false, "error": msg, "events": [] });
    CString::new(body.to_string())
        .map(|c| c.into_raw())
        .unwrap_or(ptr::null_mut())
}
