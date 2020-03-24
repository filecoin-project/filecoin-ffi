use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::Once;

use bellperson::GPU_NVIDIA_DEVICES;
use ffi_toolkit::{catch_panic_response, raw_ptr};

use super::types::{fil_GpuDeviceResponse, fil_InitLogFdResponse};

/// Protects the init off the logger.
static LOG_INIT: Once = Once::new();

/// Ensures the logger is initialized.
pub fn init_log() {
    LOG_INIT.call_once(|| {
        fil_logger::init();
    });
}
/// Initialize the logger with a file to log into
pub fn init_log_with_file(file: File) {
    LOG_INIT.call_once(|| {
        fil_logger::init_with_file(file);
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

/// Initializes the logger with a file descriptor where logs will be logged into.
///
/// This is usually a pipe that was opened on the receiving side of the logs. The logger is
/// initialized on the invocation, subsequent calls won't have any effect.
///
/// This function must be called right at the start, before any other call. Else the logger will
/// be initializes implicitely and log to stderr.
#[no_mangle]
#[cfg(not(target_os = "windows"))]
pub unsafe extern "C" fn fil_init_log_fd(log_fd: libc::c_int) -> *mut fil_InitLogFdResponse {
    catch_panic_response(|| {
        let file = File::from_raw_fd(log_fd);
        init_log_with_file(file);
        let response = fil_InitLogFdResponse::default();
        raw_ptr(response)
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::io::FromRawFd;

    use crate::util::api::{fil_get_gpu_devices, fil_init_log_fd};
    use crate::util::types::{fil_destroy_gpu_device_response, fil_destroy_init_log_fd_response};
    use log::info;

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

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_init_log_fd() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if res != 0 {
            panic!("Cannot create pipe");
        }
        let [read_fd, write_fd] = fds;

        unsafe {
            let mut reader = BufReader::new(File::from_raw_fd(read_fd));
            let mut writer = File::from_raw_fd(write_fd);

            // Without setting this env variable there won't be any log output
            env::set_var("RUST_LOG", "debug");

            let resp = fil_init_log_fd(write_fd);
            fil_destroy_init_log_fd_response(resp);

            info!("a log message");

            // Write a newline so that things don't block even if the logging doesn't work
            writer.write_all(b"\n").unwrap();

            let mut log_message = String::new();
            reader.read_line(&mut log_message).unwrap();

            assert!(log_message.ends_with("a log message\n"));
        }
    }
}
