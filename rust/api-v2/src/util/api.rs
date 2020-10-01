use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::Once;

use bellperson::GPU_NVIDIA_DEVICES;
use ffi_toolkit::{catch_panic_response, raw_ptr, rust_str_to_c_str, FCPResponseStatus};

use super::types::{fil_GpuDeviceResponseV2, fil_InitLogFdResponseV2};

/// Protects the init off the logger.
static LOG_INIT: Once = Once::new();

/// Ensures the logger is initialized.
pub fn init_log_v2() {
    LOG_INIT.call_once(|| {
        fil_logger::init();
    });
}
/// Initialize the logger with a file to log into
///
/// Returns `None` if there is already an active logger
pub fn init_log_with_file_v2(file: File) -> Option<()> {
    if LOG_INIT.is_completed() {
        None
    } else {
        LOG_INIT.call_once(|| {
            fil_logger::init_with_file(file);
        });
        Some(())
    }
}

/// Returns an array of strings containing the device names that can be used.
#[no_mangle]
pub unsafe extern "C" fn fil_get_gpu_devices_v2() -> *mut fil_GpuDeviceResponseV2 {
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

        let mut response = fil_GpuDeviceResponseV2::default();
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
pub unsafe extern "C" fn fil_init_log_fd_v2(log_fd: libc::c_int) -> *mut fil_InitLogFdResponseV2 {
    catch_panic_response(|| {
        let file = File::from_raw_fd(log_fd);
        let mut response = fil_InitLogFdResponseV2::default();
        if init_log_with_file_v2(file).is_none() {
            response.status_code = FCPResponseStatus::FCPUnclassifiedError;
            response.error_msg = rust_str_to_c_str("There is already an active logger. `fil_init_log_fd()` needs to be called before any other FFI function is called.");
        }
        raw_ptr(response)
    })
}

#[cfg(test)]
mod tests {

    use crate::util::api::fil_get_gpu_devices_v2;
    use crate::util::types::fil_destroy_gpu_device_response_v2;

    #[test]
    fn test_get_gpu_devices() {
        unsafe {
            let resp = fil_get_gpu_devices_v2();

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
            fil_destroy_gpu_device_response_v2(resp);
        }
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_init_log_fd() {
        /*

        Warning: This test is leaky. When run alongside other (Rust) tests in
        this project, `[flexi_logger] writing log line failed` lines will be
        observed in stderr, and various unrelated tests will fail.

        - @laser 20200725

         */
        use std::env;
        use std::fs::File;
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::io::FromRawFd;

        use ffi_toolkit::FCPResponseStatus;

        use crate::util::api::fil_init_log_fd_v2;
        use crate::util::types::fil_destroy_init_log_fd_response_v2;

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

            let resp = fil_init_log_fd_v2(write_fd);
            fil_destroy_init_log_fd_response_v2(resp);

            log::info!("a log message");

            // Write a newline so that things don't block even if the logging doesn't work
            writer.write_all(b"\n").unwrap();

            let mut log_message = String::new();
            reader.read_line(&mut log_message).unwrap();

            assert!(log_message.ends_with("a log message\n"));

            // Now test that there is an error when we try to init it again
            let resp_error = fil_init_log_fd_v2(write_fd);
            assert_ne!((*resp_error).status_code, FCPResponseStatus::FCPNoError);
            fil_destroy_init_log_fd_response_v2(resp_error);
        }
    }
}
