// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp

import (
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// TestObservationDedupsDuplicateKeys is the NIT test: an observation whose Reads name the
// SAME key twice must canonicalize deterministically (last-writer-wins), so two parties
// cannot produce divergent hashes from a dup-key set, and the dup collapses to one entry.
// White-box (package mcp) because it asserts the unexported sortReads collapse directly.
func TestObservationDedupsDuplicateKeys(t *testing.T) {
	mk := func(reads []ObservedFact) *ChainObservation {
		return &ChainObservation{
			ChainID:     big.NewInt(7),
			BlockNumber: 42,
			BlockHash:   common.HexToHash("0x01"),
			Timestamp:   1000,
			Tool:        "param_value",
			Reads:       reads,
		}
	}
	// Two sets that differ only in the ORDER of a duplicated "value" key. Last writer
	// ("final") must win in BOTH, so the canonical bytes and hash are identical.
	a := mk([]ObservedFact{
		{Key: "knobKey", Value: "temp"},
		{Key: "value", Value: "first"},
		{Key: "value", Value: "final"},
	})
	b := mk([]ObservedFact{
		{Key: "value", Value: "first"},
		{Key: "knobKey", Value: "temp"},
		{Key: "value", Value: "final"},
	})
	if string(a.Canonical()) != string(b.Canonical()) {
		t.Fatalf("dup-key observations not canonical-equal:\n  a=%s\n  b=%s", a.Canonical(), b.Canonical())
	}
	if a.Hash() != b.Hash() {
		t.Fatalf("dup-key observations hashed differently: %s vs %s", a.Hash().Hex(), b.Hash().Hex())
	}

	// The duplicate must collapse to a single "value" entry equal to the last writer.
	c := mk([]ObservedFact{
		{Key: "value", Value: "first"},
		{Key: "value", Value: "final"},
	})
	c.sortReads()
	count := 0
	var kept string
	for _, r := range c.Reads {
		if r.Key == "value" {
			count++
			kept = r.Value
		}
	}
	if count != 1 {
		t.Fatalf("duplicate key not collapsed: %d 'value' entries remain", count)
	}
	if kept != "final" {
		t.Fatalf("last-writer-wins broken: kept %q, want final", kept)
	}
}
