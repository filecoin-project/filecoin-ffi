package ffi

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/filecoin-project/go-address"
	proof5 "github.com/filecoin-project/specs-actors/v5/actors/runtime/proof"
)

func TestAggregate(t *testing.T) {
	f, err := os.Open("./rust/benches/agg1.json")
	if err != nil {
		t.Fatal(err)
	}

	d := json.NewDecoder(f)
	var agg proof5.AggregateSealVerifyProofAndInfos
	err = d.Decode(&agg)
	if err != nil {
		t.Fatal(err)
	}

	a, err := address.NewIDAddress(uint64(agg.Miner))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%X", a.Bytes())
	return

	_, _ = VerifyAggregateSeals(agg)
}

func BenchmarkAggregate(b *testing.B) {
	f, err := os.Open("./rust/benches/agg1.json")
	if err != nil {
		b.Fatal(err)
	}

	d := json.NewDecoder(f)
	var agg proof5.AggregateSealVerifyProofAndInfos
	err = d.Decode(&agg)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = VerifyAggregateSeals(agg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := VerifyAggregateSeals(agg)
		if !ok {
			b.Fatal(err)
		}
	}
}
