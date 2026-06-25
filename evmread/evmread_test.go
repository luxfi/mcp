// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evmread

import (
	"context"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// countingCaller records CallContract invocations and returns a fixed payload. It
// implements the four read methods of Caller and nothing else — the read-only surface.
type countingCaller struct {
	calls atomic.Int64
	ret   []byte
}

func (c *countingCaller) CallContract(_ context.Context, _ gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	c.calls.Add(1)
	return c.ret, nil
}
func (c *countingCaller) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (c *countingCaller) BlockNumber(context.Context) (uint64, error) { return 1, nil }
func (c *countingCaller) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Number: big.NewInt(1)}, nil
}

// TestNewContractRejectsBadABI proves NewContract surfaces a parse error for malformed
// ABI JSON rather than returning a half-built contract.
func TestNewContractRejectsBadABI(t *testing.T) {
	if _, err := NewContract("this is not json", common.Address{}); err == nil {
		t.Fatal("NewContract accepted malformed ABI JSON")
	}
	// A well-formed ABI binds without error.
	const goodABI = `[{"type":"function","stateMutability":"view","name":"x","inputs":[],"outputs":[{"name":"","type":"uint256"}]}]`
	if _, err := NewContract(goodABI, common.Address{}); err != nil {
		t.Fatalf("NewContract rejected valid ABI: %v", err)
	}
}

// TestBoundedEnforcesCeiling proves Bounded allows exactly `max` CallContract calls then
// fails the (max+1)th with a ceiling error, while passing the non-amplifying reads
// through unchanged.
func TestBoundedEnforcesCeiling(t *testing.T) {
	const max = 4
	cc := &countingCaller{ret: common.LeftPadBytes(big.NewInt(7).Bytes(), 32)}
	b := NewBounded(cc, max)

	for i := 0; i < max; i++ {
		if _, err := b.CallContract(context.Background(), gethereum.CallMsg{To: &common.Address{}}, nil); err != nil {
			t.Fatalf("call %d under the ceiling errored: %v", i, err)
		}
	}
	// The (max+1)th call must fail with a ceiling error.
	_, err := b.CallContract(context.Background(), gethereum.CallMsg{To: &common.Address{}}, nil)
	if err == nil {
		t.Fatal("expected a ceiling error on the (max+1)th call, got nil")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("error %q is not the ceiling error", err.Error())
	}
	// The underlying caller was hit exactly `max` times (the over-limit call short-circuits).
	if got := cc.calls.Load(); got != int64(max) {
		t.Fatalf("underlying caller hit %d times, want %d (over-limit call must not reach it)", got, max)
	}
	if got := b.Calls(); got != int64(max+1) {
		t.Fatalf("Bounded.Calls()=%d, want %d (counts the rejected attempt)", got, max+1)
	}

	// Non-amplifying reads are forwarded regardless of the ceiling.
	if _, err := b.ChainID(context.Background()); err != nil {
		t.Fatalf("ChainID passthrough errored: %v", err)
	}
	if _, err := b.BlockNumber(context.Background()); err != nil {
		t.Fatalf("BlockNumber passthrough errored: %v", err)
	}
	if _, err := b.HeaderByNumber(context.Background(), nil); err != nil {
		t.Fatalf("HeaderByNumber passthrough errored: %v", err)
	}
}

// TestBoundedZeroMaxDisablesCeiling proves max <= 0 is unbounded passthrough.
func TestBoundedZeroMaxDisablesCeiling(t *testing.T) {
	cc := &countingCaller{ret: common.LeftPadBytes(big.NewInt(1).Bytes(), 32)}
	b := NewBounded(cc, 0)
	for i := 0; i < 1000; i++ {
		if _, err := b.CallContract(context.Background(), gethereum.CallMsg{To: &common.Address{}}, nil); err != nil {
			t.Fatalf("unbounded call %d errored: %v", i, err)
		}
	}
	if got := cc.calls.Load(); got != 1000 {
		t.Fatalf("unbounded caller hit %d times, want 1000", got)
	}
}

// TestCallStructUnpacksSingleReturn proves CallStruct decodes a single uint256 return
// into a one-field path via the wrapper-struct mechanism geth requires.
func TestCallStructUnpacksSingleReturn(t *testing.T) {
	const oneUint = `[{"type":"function","stateMutability":"view","name":"v","inputs":[],"outputs":[{"name":"","type":"uint256"}]}]`
	c, err := NewContract(oneUint, common.Address{})
	if err != nil {
		t.Fatalf("NewContract: %v", err)
	}
	cc := &countingCaller{ret: common.LeftPadBytes(big.NewInt(42).Bytes(), 32)}
	got, err := CallStruct[*big.Int](context.Background(), c, cc, "v")
	if err != nil {
		t.Fatalf("CallStruct: %v", err)
	}
	if got.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("CallStruct returned %s, want 42", got)
	}
}
