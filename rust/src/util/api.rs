use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::Once;

use ffi_toolkit::catch_panic_response;

use super::types::{fil_Array, fil_Bytes, fil_GpuDeviceResponse, fil_InitLogFdResponse};

/// Protects the init off the logger.
static LOG_INIT: Once = Once::new();

/// Ensures the logger is initialized.
pub fn init_log() {
    LOG_INIT.call_once(|| {
        fil_logger::init();
    });
}
/// Initialize the logger with a file to log into
///
/// Returns `None` if there is already an active logger
pub fn init_log_with_file(file: File) -> Option<()> {
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
pub unsafe extern "C" fn fil_get_gpu_devices() -> *mut fil_GpuDeviceResponse {
    catch_panic_response(|| {
        let devices = rust_gpu_tools::Device::all();
        let devices: Vec<fil_Bytes> = devices.iter().map(|d| d.name().into()).collect();
        let devices: fil_Array<fil_Bytes> = devices.into();

        fil_GpuDeviceResponse::from(devices).into_boxed_raw()
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

        if init_log_with_file(file).is_none() {
            return fil_InitLogFdResponse::err("There is already an active logger. `fil_init_log_fd()` needs to be called before any other FFI function is called.").into_boxed_raw();
        }
        fil_InitLogFdResponse::ok(()).into_boxed_raw()
    })
}

#[cfg(test)]
mod tests {

    use crate::util::api::fil_get_gpu_devices;
    use crate::util::types::fil_destroy_gpu_device_response;

    #[test]
    #[allow(clippy::needless_collect)]
    fn test_get_gpu_devices() {
        unsafe {
            let resp = fil_get_gpu_devices();
            assert!((*resp).error_msg.is_empty());

            let strings = &(*resp).value;

            let devices: Vec<&str> = strings
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap())
                .collect();

            assert_eq!(devices.len(), (*resp).value.len());

            fil_destroy_gpu_device_response(resp);
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

        use crate::util::api::fil_init_log_fd;
        use crate::util::types::fil_destroy_init_log_fd_response;

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

            log::info!("a log message");

            // Write a newline so that things don't block even if the logging doesn't work
            writer.write_all(b"\n").unwrap();

            let mut log_message = String::new();
            reader.read_line(&mut log_message).unwrap();

            assert!(log_message.ends_with("a log message\n"));

            // Now test that there is an error when we try to init it again
            let resp_error = fil_init_log_fd(write_fd);
            assert_ne!((*resp_error).status_code, FCPResponseStatus::FCPNoError);
            fil_destroy_init_log_fd_response(resp_error);
        }
    }
}
