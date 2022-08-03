use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::sync::Once;

use anyhow::anyhow;
use safer_ffi::prelude::*;
use safer_ffi::slice::slice_boxed;

use super::types::{
    catch_panic_response, catch_panic_response_no_log, GpuDeviceResponse, InitLogFdResponse,
};

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

/// Serialize the GPU device names into a vector
#[cfg(any(feature = "opencl", feature = "cuda"))]
fn get_gpu_devices_internal() -> Vec<slice_boxed<u8>> {
    let devices = rust_gpu_tools::Device::all();

    devices
        .into_iter()
        .map(|d| d.name().into_bytes().into_boxed_slice().into())
        .collect()
}

// Return empty vector for GPU devices if cuda and opencl are disabled
#[cfg(not(any(feature = "opencl", feature = "cuda")))]
fn get_gpu_devices_internal() -> Vec<slice_boxed<u8>> {
    Vec::new()
}

/// Returns an array of strings containing the device names that can be used.
#[ffi_export]
pub fn get_gpu_devices() -> repr_c::Box<GpuDeviceResponse> {
    catch_panic_response("get_gpu_devices", || {
        let devices = get_gpu_devices_internal();
        Ok(devices.into_boxed_slice().into())
    })
}

/// Initializes the logger with a file descriptor where logs will be logged into.
///
/// This is usually a pipe that was opened on the receiving side of the logs. The logger is
/// initialized on the invocation, subsequent calls won't have any effect.
///
/// This function must be called right at the start, before any other call. Else the logger will
/// be initializes implicitely and log to stderr.
#[ffi_export]
pub fn init_log_fd(log_fd: libc::c_int) -> repr_c::Box<InitLogFdResponse> {
    catch_panic_response_no_log(|| {
        let file = unsafe { File::from_raw_fd(log_fd) };

        if init_log_with_file(file).is_none() {
            return Err(anyhow!("There is already an active logger. `init_log_fd()` needs to be called before any other FFI function is called."));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {

    #[cfg(any(feature = "opencl", feature = "cuda"))]
    #[test]
    #[allow(clippy::needless_collect)]
    fn test_get_gpu_devices() {
        use crate::util::api::get_gpu_devices;
        use crate::util::types::destroy_gpu_device_response;

        let resp = get_gpu_devices();
        assert!(resp.error_msg.is_empty());

        let strings = &resp.value;

        let devices: Vec<&str> = strings
            .iter()
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect();

        assert_eq!(devices.len(), resp.value.len());

        destroy_gpu_device_response(resp);
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

        use crate::util::api::init_log_fd;
        use crate::util::types::{destroy_init_log_fd_response, FCPResponseStatus};

        let mut fds: [libc::c_int; 2] = [0; 2];
        let res = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if res != 0 {
            panic!("Cannot create pipe");
        }
        let [read_fd, write_fd] = fds;

        let mut reader = unsafe { BufReader::new(File::from_raw_fd(read_fd)) };
        let mut writer = unsafe { File::from_raw_fd(write_fd) };

        // Without setting this env variable there won't be any log output
        env::set_var("RUST_LOG", "debug");

        let resp = init_log_fd(write_fd);
        destroy_init_log_fd_response(resp);

        log::info!("a log message");

        // Write a newline so that things don't block even if the logging doesn't work
        writer.write_all(b"\n").unwrap();

        let mut log_message = String::new();
        reader.read_line(&mut log_message).unwrap();

        assert!(log_message.ends_with("a log message\n"));

        // Now test that there is an error when we try to init it again
        let resp_error = init_log_fd(write_fd);
        assert_ne!(resp_error.status_code, FCPResponseStatus::NoError);
        destroy_init_log_fd_response(resp_error);
    }
}
