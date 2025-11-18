use safer_ffi::prelude::*;

#[derive_ReprC]
#[repr(i32)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum FvmReservationStatus {
    Ok = 0,
    ErrNotImplemented = 1,
    ErrInsufficientFundsAtBegin = 2,
    ErrSessionOpen = 3,
    ErrSessionClosed = 4,
    ErrNonZeroRemainder = 5,
    ErrPlanTooLarge = 6,
    ErrOverflow = 7,
    ErrReservationInvariant = 8,
}

#[ffi_export]
pub fn FVM_DestroyReservationErrorMessage(error_msg_ptr: *mut u8, error_msg_len: usize) {
    if error_msg_ptr.is_null() || error_msg_len == 0 {
        return;
    }

    // Safety: the pointer and length are produced by the FFI side in
    // FVM_BeginReservations/FVM_EndReservations using the same layout.
    unsafe {
        let layout = match std::alloc::Layout::array::<u8>(error_msg_len) {
            Ok(layout) => layout,
            Err(_) => return,
        };
        std::alloc::dealloc(error_msg_ptr, layout);
    }
}

fn clear_reservation_error_message_out(
    error_msg_ptr_out: *mut *const u8,
    error_msg_len_out: *mut usize,
) {
    if !error_msg_ptr_out.is_null() {
        // Safety: caller provided a valid pointer.
        unsafe { *error_msg_ptr_out = std::ptr::null() };
    }
    if !error_msg_len_out.is_null() {
        // Safety: caller provided a valid pointer.
        unsafe { *error_msg_len_out = 0 };
    }
}

fn set_reservation_error_message_out(
    error_msg_ptr_out: *mut *const u8,
    error_msg_len_out: *mut usize,
    message: &str,
) {
    if error_msg_ptr_out.is_null() || error_msg_len_out.is_null() {
        return;
    }

    let bytes = message.as_bytes();
    if bytes.is_empty() {
        return;
    }

    let layout = match std::alloc::Layout::array::<u8>(bytes.len()) {
        Ok(layout) => layout,
        Err(_) => return,
    };

    // Safety: allocate and copy the message bytes for the host. The host is
    // responsible for freeing the allocation via FVM_DestroyReservationErrorMessage.
    unsafe {
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            return;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        *error_msg_ptr_out = ptr as *const u8;
        *error_msg_len_out = bytes.len();
    }
}

#[ffi_export]
pub fn FVM_BeginReservations(
    cbor_plan_ptr: *const u8,
    cbor_plan_len: usize,
    error_msg_ptr_out: *mut *const u8,
    error_msg_len_out: *mut usize,
) -> FvmReservationStatus {
    clear_reservation_error_message_out(error_msg_ptr_out, error_msg_len_out);

    // Empty plans are a no-op and must not enter reservation mode.
    if cbor_plan_len == 0 {
        return FvmReservationStatus::Ok;
    }

    if cbor_plan_ptr.is_null() {
        set_reservation_error_message_out(
            error_msg_ptr_out,
            error_msg_len_out,
            "reservation invariant violated: null plan pointer",
        );
        return FvmReservationStatus::ErrReservationInvariant;
    }

    set_reservation_error_message_out(
        error_msg_ptr_out,
        error_msg_len_out,
        "reservations not implemented",
    );
    FvmReservationStatus::ErrNotImplemented
}

#[ffi_export]
pub fn FVM_EndReservations(
    error_msg_ptr_out: *mut *const u8,
    error_msg_len_out: *mut usize,
) -> FvmReservationStatus {
    clear_reservation_error_message_out(error_msg_ptr_out, error_msg_len_out);

    set_reservation_error_message_out(
        error_msg_ptr_out,
        error_msg_len_out,
        "reservations not implemented",
    );
    FvmReservationStatus::ErrNotImplemented
}
