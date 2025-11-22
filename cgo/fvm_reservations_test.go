//go:build cgo
// +build cgo

package cgo

/*
#cgo LDFLAGS: -L${SRCDIR}/..
#cgo pkg-config: ${SRCDIR}/../filcrypto.pc
#include "../filcrypto.h"
*/

import (
	"testing"
)

// TestFvmBeginReservationsErrorMessage verifies that the cgo wrapper surfaces a
// non-empty error message for a failing reservation plan and that the FFI
// allocation can be freed without panics.
func TestFvmBeginReservationsErrorMessage(t *testing.T) {
	// Force a non-empty plan length with a null pointer to trigger an invariant
	// error in the FFI without relying on a full FVM executor.
	plan := SliceRefUint8{len: 1}

	status, msg := FvmBeginReservations(plan)
	if status == 0 {
		t.Fatalf("expected non-OK reservation status for null plan pointer, got %d", status)
	}
	if msg == "" {
		t.Fatalf("expected non-empty reservation error message")
	}
}

// TestFvmEndReservationsErrorMessage verifies that the cgo wrapper surfaces a
// non-empty error message when ending reservations without an active session.
func TestFvmEndReservationsErrorMessage(t *testing.T) {
	status, msg := FvmEndReservations()
	if status == 0 {
		t.Fatalf("expected non-OK reservation status when ending without a session")
	}
	if msg == "" {
		t.Fatalf("expected non-empty reservation end error message")
	}
}
