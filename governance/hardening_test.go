// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"context"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"

	"github.com/luxfi/mcp"
)

// ----------------------------------------------------------------------------
// Test evmread.Caller stub (read-only; it implements only the four read methods, so it
// can never grow a write path — same surface the production client exposes).
// ----------------------------------------------------------------------------

// countingThoughtCaller returns a minimal still-Open thought for every getThought call and
// counts CallContract invocations. taskCount is large so pending_operations wants to scan a
// big window — letting us prove the per-request eth_call ceiling bites first.
type countingThoughtCaller struct {
	calls     atomic.Int64
	taskCount uint64
}

func (c *countingThoughtCaller) CallContract(_ context.Context, call gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	n := c.calls.Add(1)
	// We don't decode the selector; we answer based on output shape the caller expects.
	// pending_operations issues taskCount() (one uint256) then getThought() (a Thought
	// tuple) repeatedly. Distinguish by returning a uint256 for the FIRST call and a Thought
	// tuple thereafter — the unpacker only needs well-formed bytes.
	if n == 1 {
		return encodeUint256(new(big.Int).SetUint64(c.taskCount)), nil
	}
	return encodeOpenThought(), nil
}
func (c *countingThoughtCaller) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (c *countingThoughtCaller) BlockNumber(context.Context) (uint64, error) { return c.taskCount, nil }
func (c *countingThoughtCaller) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Number: new(big.Int).SetUint64(c.taskCount), Time: 1_700_000_000}, nil
}

// stubSurface builds a governance Surface over a custom evmread.Caller with non-zero
// contract addresses (so newSurface accepts the config).
func stubSurface(t *testing.T, ec EthCaller) *Surface {
	t.Helper()
	addr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	g, err := NewWithCaller(ec, Config{
		AIParams:          addr,
		AIGovernor:        addr,
		AIThoughtRegistry: addr,
		AIReputation:      addr,
	})
	if err != nil {
		t.Fatalf("stub surface: %v", err)
	}
	return g
}

// TestPerRequestCallCeiling is the MEDIUM-4 test: one tools/call cannot issue an unbounded
// number of eth_calls. The ceiling lives in the governance Surface (it knows its read
// patterns). With a small ceiling and a chain that would otherwise invite a deep scan,
// pending_operations bails with a ceiling error rather than hammering the upstream thousands
// of times.
func TestPerRequestCallCeiling(t *testing.T) {
	caller := &countingThoughtCaller{taskCount: 100000}
	g := stubSurface(t, caller)
	g.maxCallsPerRequest = 8 // tiny ceiling for the test
	srv, err := mcp.NewServer(g)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// pending_operations with a large limit would normally scan many tasks. The ceiling must
	// stop it well before taskCount.
	_, err = srv.CallTool(context.Background(), toolPendingOperations, map[string]interface{}{"limit": 200})
	if err == nil {
		t.Fatal("expected a per-request ceiling error, got nil")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("error %q is not the ceiling error", err.Error())
	}
	// The wrapper allows exactly `max` calls then fails the (max+1)th, so total CallContract
	// calls is bounded at max+1 — proving we did NOT run away to taskCount. (ChainID/
	// BlockNumber/HeaderByNumber are not counted; only CallContract amplifies.)
	if got := caller.calls.Load(); got > int64(g.maxCallsPerRequest+1) {
		t.Fatalf("issued %d eth_calls, ceiling was %d — runaway not stopped", got, g.maxCallsPerRequest)
	}
	t.Logf("call ceiling stopped the scan at %d eth_calls (max %d)", caller.calls.Load(), g.maxCallsPerRequest)
}

// TestArgInputLengthCapped is the LOW test: an absurdly long string/integer argument is
// rejected at the boundary BEFORE parsing (no giant big.Int or hex decode).
func TestArgInputLengthCapped(t *testing.T) {
	bigStr := strings.Repeat("9", maxArgStringLen+1)
	// argString path (knobKey).
	if _, err := argString(map[string]interface{}{"knobKey": bigStr}, "knobKey"); err == nil {
		t.Fatal("expected argString to reject an over-long string")
	}
	// toBigInt string path (task/round ids).
	if _, err := argUint256(map[string]interface{}{"taskId": bigStr}, "taskId"); err == nil {
		t.Fatal("expected argUint256 to reject an over-long integer string")
	}
	// A normal value still works.
	if _, err := argString(map[string]interface{}{"knobKey": "temperature"}, "knobKey"); err != nil {
		t.Fatalf("normal knobKey wrongly rejected: %v", err)
	}
}

// TestArgLimitClampedToMax is the MEDIUM-4 boundary test: limit is clamped to maxLimit.
func TestArgLimitClampedToMax(t *testing.T) {
	if got := argLimit(map[string]interface{}{"limit": float64(1_000_000)}, 16); got != maxLimit {
		t.Fatalf("argLimit(1e6)=%d, want clamp to %d", got, maxLimit)
	}
	if got := argLimit(map[string]interface{}{}, 16); got != 16 {
		t.Fatalf("argLimit(absent)=%d, want default 16", got)
	}
	if got := argLimit(map[string]interface{}{"limit": float64(10)}, 16); got != 10 {
		t.Fatalf("argLimit(10)=%d, want 10", got)
	}
}

// ----------------------------------------------------------------------------
// helpers to synthesize ABI-encoded return values for the counting stub
// ----------------------------------------------------------------------------

// encodeUint256 returns the 32-byte big-endian encoding of v (an ABI uint256 return).
func encodeUint256(v *big.Int) []byte {
	return common.LeftPadBytes(v.Bytes(), 32)
}

// encodeOpenThought returns a minimally-valid ABI encoding of the AIGovernor Thought tuple
// with Status=Open. The tuple has two dynamic fields (knobKey string at the end is the only
// string; everything else is static within the head), so we hand-assemble the head + the
// string tail. We only need the unpacker to succeed and Status to read Open.
func encodeOpenThought() []byte {
	// The Thought tuple is a single dynamic struct return, so the outer return is one offset
	// word pointing at the tuple, then the tuple's own head, then its dynamic tail (knobKey).
	// Build it explicitly.
	zero32 := make([]byte, 32)
	word := func(n uint64) []byte { return common.LeftPadBytes(new(big.Int).SetUint64(n).Bytes(), 32) }

	// Tuple field layout (mirrors abi.go Thought / thoughtTuple), all padded to 32 bytes in
	// the tuple head; knobKey is dynamic so its head slot is an offset into the tuple. Fields
	// in order:
	//  0 modelSpecHash bytes32
	//  1 promptHash    bytes32
	//  2 evidenceHash  bytes32
	//  3 n             uint8
	//  4 threshold     uint8
	//  5 openedAt      uint64
	//  6 deadline      uint64
	//  7 opener        address
	//  8 status        uint8   <- must be Open(1)
	//  9 submissionCount uint8
	// 10 knobKey       string  (dynamic -> offset)
	// 11 canonicalVote uint8
	// 12 canonicalBucket uint16
	// 13 agreeCount    uint8
	// 14 evidenceRoot  bytes32
	// 15 commitReveal  bool
	// 16 commitDeadline uint64
	// 17 revealDeadline uint64
	const nFields = 18
	head := make([]byte, 0, nFields*32)
	appendWord := func(b []byte) { head = append(head, b...) }

	appendWord(zero32)                   // 0 modelSpecHash
	appendWord(zero32)                   // 1 promptHash
	appendWord(zero32)                   // 2 evidenceHash
	appendWord(word(0))                  // 3 n
	appendWord(word(0))                  // 4 threshold
	appendWord(word(0))                  // 5 openedAt
	appendWord(word(0))                  // 6 deadline
	appendWord(zero32)                   // 7 opener
	appendWord(word(uint64(statusOpen))) // 8 status = Open
	appendWord(word(0))                  // 9 submissionCount
	// 10 knobKey offset: filled after we know the head size. Placeholder for now.
	knobOffsetIdx := len(head)
	appendWord(zero32)  // 10 knobKey offset (placeholder)
	appendWord(word(0)) // 11 canonicalVote
	appendWord(word(0)) // 12 canonicalBucket
	appendWord(word(0)) // 13 agreeCount
	appendWord(zero32)  // 14 evidenceRoot
	appendWord(word(0)) // 15 commitReveal (false)
	appendWord(word(0)) // 16 commitDeadline
	appendWord(word(0)) // 17 revealDeadline

	// knobKey tail: offset is relative to the START of the tuple head. Empty string = length
	// 0 (one zero word).
	tupleHeadLen := uint64(len(head))
	copy(head[knobOffsetIdx:knobOffsetIdx+32], word(tupleHeadLen))
	tail := word(0) // string length 0

	tuple := append(head, tail...)

	// Outer return: one offset word (0x20) to the tuple.
	out := append(word(32), tuple...)
	return out
}
