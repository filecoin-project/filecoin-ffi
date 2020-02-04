use bellperson::GPU_NVIDIA_DEVICES;
use ffi_toolkit::{catch_panic_response, raw_ptr};

use super::types::GpuDeviceResponse;
use std::ffi::CString;

/// Returns an array of strings containing the device names that can be used.
#[no_mangle]
pub unsafe extern "C" fn get_gpu_devices() -> *mut GpuDeviceResponse {
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

        let mut response = GpuDeviceResponse::default();
        response.devices_len = n;
        response.devices_ptr = dyn_array as *const *const libc::c_char;

        raw_ptr(response)
    })
}

#[cfg(test)]
mod tests {
    use crate::util::api::get_gpu_devices;
    use crate::util::types::destroy_gpu_device_response;

    #[test]
    fn test_get_gpu_devices() {
        unsafe {
            let resp = get_gpu_devices();

            let strings = std::slice::from_raw_parts_mut(
                (*resp).devices_ptr as *mut *mut libc::c_char,
                (*resp).devices_len as usize,
            );

            let devices: Vec<String> = strings
                .into_iter()
                .map(|s| {
                    std::ffi::CStr::from_ptr(*s)
                        .to_str()
                        .unwrap_or("Unknown")
                        .to_owned()
                })
                .collect();

            assert_eq!(devices.len(), (*resp).devices_len);
            destroy_gpu_device_response(resp);
        }
    }
}
