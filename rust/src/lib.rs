mod error;
mod rules;
mod sni;
mod tor;
mod vpn;

use jni::objects::{JClass, JString, JObject, JByteArray};
use jni::sys::{jbyteArray, jint, jboolean, JNI_TRUE, JNI_FALSE};
use jni::JNIEnv;
use std::path::PathBuf;

// ------------------------------------------------------------
// JNI functions for SNI rules
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRule(
    mut env: JNIEnv, _class: JClass, domain: JString, replacement: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    let repl_str: String = env.get_string(&replacement).unwrap().into();
    if let Err(e) = rules::set_rule(&domain_str, &repl_str) {
        log::error!("Failed to set SNI rule: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_removeSniRule(
    mut env: JNIEnv, _class: JClass, domain: JString,
) {
    let domain_str: String = env.get_string(&domain).unwrap().into();
    if let Err(e) = rules::remove_rule(&domain_str) {
        log::error!("Failed to remove SNI rule: {}", e);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_setSniRulesPath(
    mut env: JNIEnv, _class: JClass, path: JString,
) {
    let path_str: String = env.get_string(&path).unwrap().into();
    rules::set_storage_path(PathBuf::from(path_str));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getSniRulesJson<'a>(
    env: JNIEnv<'a>, _class: JClass<'a>,
) -> JString<'a> {
    let rules = rules::get_all_rules();
    let json = serde_json::to_string(&rules).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap()
}

// ------------------------------------------------------------
// JNI for Tor
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startTor(
    _env: JNIEnv, _class: JClass,
) -> jint {
    tor::start_sync()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_isTorRunning(
    _env: JNIEnv, _class: JClass,
) -> jboolean {
    if tor::is_running_sync() { JNI_TRUE } else { JNI_FALSE }
}

// ------------------------------------------------------------
// JNI for SNI modification
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_modifySni(
    env: JNIEnv, _class: JClass, packet: jbyteArray,
) -> jbyteArray {
    // Convert to JByteArray for safe operations
    let jba = unsafe { JByteArray::from(JObject::from_raw(packet)) };
    let len = match env.get_array_length(&jba) {
        Ok(l) => l as usize,
        Err(_) => return packet,
    };
    let mut data = vec![0u8; len];
    let data_i8: &mut [i8] = unsafe {
        std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut i8, len)
    };
    if env.get_byte_array_region(&jba, 0, data_i8).is_err() {
        return packet;
    }

    // Extract SNI to find rule
    if let Some(original_sni) = sni::extract_sni(&data) {
        if let Some(new_sni) = rules::get_replacement(&original_sni) {
            if let Some(modified) = sni::replace_sni(&data, &new_sni) {
                let new_array = match env.new_byte_array(modified.len() as jint) {
                    Ok(arr) => arr,
                    Err(_) => return packet,
                };
                let new_data_i8: &[i8] = unsafe {
                    std::slice::from_raw_parts(modified.as_ptr() as *const i8, modified.len())
                };
                if env.set_byte_array_region(&new_array, 0, new_data_i8).is_err() {
                    return packet;
                }
                return new_array.into_inner();
            }
        }
    }
    packet
}

// ------------------------------------------------------------
// JNI for VPN (placeholder)
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_startVpn(
    _env: JNIEnv, _class: JClass,
) {
    log::info!("VPN start – implementation pending");
}

// ------------------------------------------------------------
// Logging
// ------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_initLogging(
    _env: JNIEnv, _class: JClass,
) {
    env_logger::init();
    log::info!("II VPN Rust core initialized");
}

// Version info
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_iivpn_VpnService_getVersion<'a>(
    env: JNIEnv<'a>, _class: JClass<'a>,
) -> JString<'a> {
    let version = format!("{}.{}.{}", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR"), env!("CARGO_PKG_VERSION_PATCH"));
    env.new_string(version).unwrap()
}
