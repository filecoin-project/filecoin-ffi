package cgo

/*
#cgo linux LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-unresolved-symbols=ignore-all
#cgo darwin LDFLAGS: ${SRCDIR}/../libfilcrypto.a -Wl,-undefined,dynamic_lookup
#include "../filcrypto.h"
#include <stdlib.h>
*/
import "C"

// libs_generated.go, installed alongside libfilcrypto.a, links the native
// libraries it depends on. Referencing it here fails the build when it is
// missing, rather than leaving those symbols unresolved until runtime.
var _ = filcryptoLibs
