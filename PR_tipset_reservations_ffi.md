# feat: add FVM reservation Begin/End FFI with error messages

This PR wires the ref‑fvm reservation session API through filecoin‑ffi and extends the Begin/End FFI to return short human‑readable error messages alongside status codes. Lotus uses the status codes for gating and the messages for logging; ref‑fvm remains network‑version agnostic.

## Summary

- Add C ABI exports for `FVM_BeginReservations` / `FVM_EndReservations` with status codes plus optional error strings.
- Provide Go wrappers that map status codes to typed errors and attach the engine‑provided message when present.
- Keep the status‑code contract as the only semantic signal for hosts (messages are logging only).

## Changes

### Cgo surface and Go bindings

- **`cgo/fvm.go`**
  - Extend C declarations:
    - `int32_t FVM_BeginReservations(const uint8_t *cbor_plan_ptr, size_t cbor_plan_len, const uint8_t **error_msg_ptr, size_t *error_msg_len);`
    - `int32_t FVM_EndReservations(const uint8_t **error_msg_ptr, size_t *error_msg_len);`
    - `void FVM_DestroyReservationErrorMessage(uint8_t *error_msg_ptr, size_t error_msg_len);`
  - Add Go wrappers:
    - `func FvmBeginReservations(plan SliceRefUint8) (int32, string)`
    - `func FvmEndReservations() (int32, string)`
  - Behaviour:
    - Call the C ABI, copy the returned message (if any) into Go memory, and free the FFI allocation via `FVM_DestroyReservationErrorMessage`.

- **`fvm.go`**
  - Define typed reservation errors:
    - `ErrReservationsNotImplemented`
    - `ErrReservationsInsufficientFunds`
    - `ErrReservationsSessionOpen`
    - `ErrReservationsSessionClosed`
    - `ErrReservationsNonZeroRemainder`
    - `ErrReservationsPlanTooLarge`
    - `ErrReservationsOverflow`
    - `ErrReservationsInvariantViolation`
  - Implement:
    - `ReservationStatusToError(code int32) error` mapping raw status codes to these sentinels.
    - `(*FVM).BeginReservations(plan []byte) error`:
      - Calls `cgo.FvmBeginReservations`, maps status to a typed error, and if a non‑empty message is present, wraps the error as `fmt.Errorf("%w: %s", baseErr, msg)`.
    - `(*FVM).EndReservations() error` with analogous behaviour.
  - These APIs are called by Lotus’ FVM wrapper (`chain/vm/fvm.go`) when orchestrating Begin/End reservations.

### Rust FFI glue

- **`rust/src/fvm/machine.rs`**
  - Introduce helper:
    - `fn set_reservation_error_message_out(error_msg_ptr_out: *mut *const u8, error_msg_len_out: *mut usize, msg: &str)` to allocate and expose a short message over the FFI.
  - Add `fn map_reservation_error_to_status(err: ReservationError, error_msg_ptr_out: *mut *const u8, error_msg_len_out: *mut usize) -> FvmReservationStatus` that:
    - Maps `fvm4::executor::ReservationError` variants to `FvmReservationStatus`.
    - Sets a short message string for non‑OK statuses, e.g.:
      - `ErrInsufficientFundsAtBegin { sender }` → message including sender ID.
      - `ErrReservationInvariant(reason)` → message including the invariant description.
      - Lock poisoning or missing executor → `ErrReservationInvariant` with a descriptive message.
  - Update:
    - `FVM_BeginReservations(...) -> FvmReservationStatus` to:
      - Decode the plan, look up the current `InnerFvmMachine`, and call `executor.begin_reservations(plan)`.
      - On error, call `map_reservation_error_to_status` to populate both status and message.
    - `FVM_EndReservations() -> FvmReservationStatus` similarly calls `executor.end_reservations()` and uses the mapping helper on error.
  - Add tests that:
    - Exercise `map_reservation_error_to_status` for representative errors (`InsufficientFundsAtBegin`, `ReservationInvariant`) and verify that:
      - Status values are as expected.
      - Returned messages are non‑empty and contain the relevant context.
      - `FVM_DestroyReservationErrorMessage` can free the allocation safely.

### Tests

- **`cgo/fvm_reservations_test.go`**
  - `TestFvmBeginReservationsErrorMessage`:
    - Calls `FvmBeginReservations` with a deliberately invalid plan pointer/length pair to trigger a Reservation invariant error.
    - Asserts that the status code is non‑zero and the message is non‑empty.
  - `TestFvmEndReservationsErrorMessage`:
    - Calls `FvmEndReservations` without an active session.
    - Asserts non‑zero status and non‑empty message.

## Notes

- Hosts must continue to base consensus decisions purely on status codes (mapped to typed errors on the Go side). The new messages are for logging and operator diagnostics only.
- The FFI remains agnostic to network version; activation and gating are handled entirely in Lotus using the tipset network version and feature flags.

