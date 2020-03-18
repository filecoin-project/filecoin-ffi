use std::sync::Once;

use bellperson::GPU_NVIDIA_DEVICES;
use ffi_toolkit::{catch_panic_response, raw_ptr};

use super::types::fil_GpuDeviceResponse;
use std::ffi::CString;

/// Protects the init off the logger.
static LOG_INIT: Once = Once::new();

/// Ensures the logger is initialized.
pub fn init_log() {
    LOG_INIT.call_once(|| {
        fil_logger::init();
    });
}

/// Returns an array of strings containing the device names that can be used.
#[no_mangle]
pub unsafe extern "C" fn fil_get_gpu_devices() -> *mut fil_GpuDeviceResponse {
    catch_panic_response(|| {
        let n = GPU_NVIDIA_DEVICES.len();

        let devices: Vec<*const libc::c_char> = GPU_NVIDIA_DEVICES
            .iter()
            .map(|d| d.name().unwrap_or_else(|_| "Unknown".to_string()))
            .map(|d| {
                CString::new(d)
                    .unwrap_or_else(|_| CString::new("Unknown").unwrap())
                    .into_raw() as *const libc::c_char
            })
            .collect();

        let dyn_array = Box::into_raw(devices.into_boxed_slice());

        let mut response = fil_GpuDeviceResponse::default();
        response.devices_len = n;
        response.devices_ptr = dyn_array as *const *const libc::c_char;

        raw_ptr(response)
    })
}

#[cfg(test)]
mod tests {
    use crate::util::api::fil_get_gpu_devices;
    use crate::util::types::fil_destroy_gpu_device_response;

    #[test]
    fn test_get_gpu_devices() {
        unsafe {
            let resp = fil_get_gpu_devices();

            let strings = std::slice::from_raw_parts_mut(
                (*resp).devices_ptr as *mut *mut libc::c_char,
                (*resp).devices_len as usize,
            );

            let devices: Vec<String> = strings
                .iter_mut()
                .map(|s| {
                    std::ffi::CStr::from_ptr(*s)
                        .to_str()
                        .unwrap_or("Unknown")
                        .to_owned()
                })
                .collect();

            assert_eq!(devices.len(), (*resp).devices_len);
            fil_destroy_gpu_device_response(resp);
        }
    }
}
