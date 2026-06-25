// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"context"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"
)

// TestPendingOperationsAnnotatesDeadlineAndTruncation is the MEDIUM-5 test. It proves:
//   - a still-Open task whose voting window has CLOSED is returned with deadlinePassed=true
//     (so the LLM knows the window is over even though settle was never called), while a
//     fresh Open task reads deadlinePassed=false;
//   - when more tasks exist than the scan window inspects, truncated=true and scannedFrom
//     marks the lowest id seen (the list is honestly flagged as incomplete).
func TestPendingOperationsAnnotatesDeadlineAndTruncation(t *testing.T) {
	ops := genKeys(t, 1)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()
	for _, k := range ops {
		env.registerOperator(k)
	}

	spec := specHash("pending-ops-spec")

	// Task 0: open it, then advance PAST its 1h window without settling -> still Open,
	// but deadlinePassed must be true.
	t0 := env.openThought(spec, "knob-0", 1)
	env.c.advanceSeconds(2 * 3600)

	// Task 1: open it fresh (deadline in the future) -> Open, deadlinePassed false.
	t1 := env.openThought(spec, "knob-1", 1)

	res := callTool(t, srv, toolPendingOperations, map[string]interface{}{})
	pending := res["pending"].([]interface{})

	// Both tasks are Open, so both appear. Index them by taskId.
	byID := map[string]map[string]interface{}{}
	for _, p := range pending {
		m := p.(map[string]interface{})
		byID[m["taskId"].(string)] = m
	}
	p0, ok := byID[t0.String()]
	if !ok {
		t.Fatalf("task 0 missing from pending: %v", pending)
	}
	p1, ok := byID[t1.String()]
	if !ok {
		t.Fatalf("task 1 missing from pending: %v", pending)
	}
	if p0["deadlinePassed"] != true {
		t.Fatalf("task 0 deadlinePassed=%v, want true (window closed, unsettled)", p0["deadlinePassed"])
	}
	if p1["deadlinePassed"] != false {
		t.Fatalf("task 1 deadlinePassed=%v, want false (fresh window)", p1["deadlinePassed"])
	}

	// With a tiny limit and only the tail scanned, truncation must be reported honestly.
	// Open several more tasks so taskCount exceeds a limit=1 window.
	for i := 0; i < 3; i++ {
		env.openThought(spec, "knob-extra", 1)
	}
	// Pass limit as float64 to mirror JSON-decoded args (the real transport path).
	small := callTool(t, srv, toolPendingOperations, map[string]interface{}{"limit": float64(1)})
	// We asked for at most 1 result; with many open tasks at the tail it returns 1.
	if got := len(small["pending"].([]interface{})); got != 1 {
		t.Fatalf("limit=1 returned %d pending, want 1", got)
	}
	if small["truncated"] != true {
		t.Fatalf("truncated=%v, want true (older tasks below the window were not inspected)", small["truncated"])
	}
	// scannedFrom must be > 0 (we did not reach task 0).
	sf, ok := new(big.Int).SetString(small["scannedFrom"].(string), 10)
	if !ok || sf.Sign() <= 0 {
		t.Fatalf("scannedFrom=%v, want a positive lowest-scanned id", small["scannedFrom"])
	}
}

// TestPendingOperationsNotTruncatedWhenAllScanned proves truncated=false when the scan
// reaches task 0 (the window covers everything), so the flag is meaningful (not always on).
func TestPendingOperationsNotTruncatedWhenAllScanned(t *testing.T) {
	ops := genKeys(t, 1)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()
	for _, k := range ops {
		env.registerOperator(k)
	}
	spec := specHash("pending-small-spec")
	// Just two tasks; the default scan floor (64) covers them to task 0.
	env.openThought(spec, "a", 1)
	env.openThought(spec, "b", 1)

	res := callTool(t, srv, toolPendingOperations, map[string]interface{}{})
	if res["truncated"] != false {
		t.Fatalf("truncated=%v, want false (scan reached task 0)", res["truncated"])
	}
	if res["scannedFrom"] != "0" {
		t.Fatalf("scannedFrom=%v, want 0 (inspected down to genesis task)", res["scannedFrom"])
	}
}

// TestObservationVerifyRejectsChainMismatch is the LOW test: Verify must reject an
// observation taken on a DIFFERENT chain id, even when block number/hash would match.
func TestObservationVerifyRejectsChainMismatch(t *testing.T) {
	ops := genKeys(t, 1)
	_, env := newEVMChain(t, ops)

	obs, err := newObservation(context.Background(), env.c, toolChainState, nil)
	if err != nil {
		t.Fatalf("newObservation: %v", err)
	}
	// Sanity: it verifies on its own chain.
	if fresh, err := obs.Verify(context.Background(), env.c, 0); err != nil || !fresh {
		t.Fatalf("fresh observation rejected on its own chain: fresh=%v err=%v", fresh, err)
	}

	// Forge a wrong chain id on the observation; Verify must reject as a chain mismatch.
	wrong := &ChainObservation{
		ChainID:     new(big.Int).Add(obs.ChainID, big.NewInt(1)),
		BlockNumber: obs.BlockNumber,
		BlockHash:   obs.BlockHash,
		Timestamp:   obs.Timestamp,
		Tool:        toolChainState,
	}
	fresh, err := wrong.Verify(context.Background(), env.c, 1000)
	if fresh {
		t.Fatal("observation with mismatched chainId passed Verify")
	}
	if err == nil {
		t.Fatal("expected a chain-mismatch error, got nil")
	}
	t.Logf("chain mismatch correctly rejected: %v", err)

	// A nil chainId is also a mismatch (cannot be trusted).
	nilCID := &ChainObservation{BlockNumber: obs.BlockNumber, BlockHash: obs.BlockHash, Tool: toolChainState}
	if fresh, _ := nilCID.Verify(context.Background(), env.c, 1000); fresh {
		t.Fatal("observation with nil chainId passed Verify")
	}
}

// TestObservationDedupsDuplicateKeys is the NIT test: an observation whose Reads name the
// SAME key twice must canonicalize deterministically (last-writer-wins), so two parties
// cannot produce divergent hashes from a dup-key set, and the dup collapses to one entry.
func TestObservationDedupsDuplicateKeys(t *testing.T) {
	mk := func(reads []ObservedFact) *ChainObservation {
		return &ChainObservation{
			ChainID:     big.NewInt(7),
			BlockNumber: 42,
			BlockHash:   common.HexToHash("0x01"),
			Timestamp:   1000,
			Tool:        toolParamValue,
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
