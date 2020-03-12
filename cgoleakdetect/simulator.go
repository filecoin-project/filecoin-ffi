package main

import (
	"crypto/rand"
	"fmt"

	ffi "github.com/filecoin-project/filecoin-ffi"
)

func main() {
	bytes, err := generateRandomBytes(100)
	if err != nil {
		panic(err)
	}

	digest := ffi.Hash(bytes)
	fmt.Printf("digest: %+v\n", digest)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
