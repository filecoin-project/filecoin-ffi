use std::ffi::CString;

use bellperson::GPU_NVIDIA_DEVICES;
use ffi_toolkit::{catch_panic_response, raw_ptr};

use super::types::GpuDeviceResponse;

/// Returns an array of strings containing the device names that can be used.
#[no_mangle]
pub unsafe extern "C" fn get_gpu_devices() -> *mut GpuDeviceResponse {
    catch_panic_response(|| {
        let devices: Vec<*const i8> = GPU_NVIDIA_DEVICES
            .iter()
            .map(|device| {
                let name = device.name().unwrap_or("Unknown".to_string());
                CString::new(&name[..]).unwrap().as_ptr()
            })
            .collect();
        let mut response = GpuDeviceResponse::default();
        response.devices_len = devices.len();
        response.devices_ptr = devices.as_ptr();

        raw_ptr(response)
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::slice::from_raw_parts;

    use crate::util::api::get_gpu_devices;
    use crate::util::types::destroy_gpu_device_response;

    #[test]
    fn test_get_gpu_devices() {
        unsafe {
            let resp = get_gpu_devices();
            let devices: Vec<&str> = from_raw_parts((*resp).devices_ptr, (*resp).devices_len)
                .iter()
                .map(|name_ptr| CStr::from_ptr(*name_ptr).to_str().unwrap())
                .collect();
            assert_eq!(devices.len(), (*resp).devices_len);
            destroy_gpu_device_response(resp);
        }
    }
}
