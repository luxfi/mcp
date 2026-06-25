// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"bufio"
	"context"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// ----------------------------------------------------------------------------
// Test EthCaller stubs (read-only; they implement only the four read methods, so
// they can never grow a write path — same surface the production client exposes).
// ----------------------------------------------------------------------------

// blockingCaller's CallContract blocks until the call's context is cancelled, modeling a
// hung upstream RPC. It returns the context error so the per-call timeout surfaces.
type blockingCaller struct{}

func (blockingCaller) CallContract(ctx context.Context, _ gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockingCaller) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (blockingCaller) BlockNumber(context.Context) (uint64, error) { return 1, nil }
func (blockingCaller) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return &types.Header{Number: big.NewInt(1), Time: 1_700_000_000}, nil
}

// countingThoughtCaller returns a minimal still-Open thought for every getThought call
// and counts CallContract invocations. taskCount is large so pending_operations wants to
// scan a big window — letting us prove the per-request eth_call ceiling bites first.
type countingThoughtCaller struct {
	calls     atomic.Int64
	taskCount uint64
}

func (c *countingThoughtCaller) CallContract(_ context.Context, call gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	n := c.calls.Add(1)
	// We don't decode the selector; we answer based on output shape the caller expects.
	// pending_operations issues taskCount() (one uint256) then getThought() (a Thought
	// tuple) repeatedly. Distinguish by returning a uint256 for the FIRST call and a
	// Thought tuple thereafter — the unpacker only needs well-formed bytes.
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

// stubServer builds a Server over a custom EthCaller with non-zero contract addresses
// (so newServer accepts the config) and small test budgets.
func stubServer(t *testing.T, ec EthCaller) *Server {
	t.Helper()
	addr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	srv, err := NewWithCaller(ec, Config{
		AIParams:          addr,
		AIGovernor:        addr,
		AIThoughtRegistry: addr,
		AIReputation:      addr,
	})
	if err != nil {
		t.Fatalf("stub server: %v", err)
	}
	return srv
}

// TestPerCallTimeoutDoesNotWedgeServer is the HIGH-3 test: a hung upstream RPC must not
// wedge the stdio loop. With a tiny call budget, a tools/call that blocks on a never-
// returning CallContract returns a timeout (isError) AND the server still answers the
// NEXT request on the same stream.
func TestPerCallTimeoutDoesNotWedgeServer(t *testing.T) {
	srv := stubServer(t, blockingCaller{})
	srv.callTimeout = 100 * time.Millisecond // shrink so the test is fast

	// First request hits the blocking caller (param_value issues an eth_call -> blocks
	// until the per-call deadline). Second request is chain_state, which the stub answers
	// without an eth_call, proving the loop survived.
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"param_value","arguments":{"modelSpecHash":"0x` + strings.Repeat("00", 32) + `","knobKey":"x"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"chain_state","arguments":{}}}`,
	}, "\n") + "\n"

	start := time.Now()
	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	elapsed := time.Since(start)

	resps := decodeLines(t, out.String())
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d:\n%s", len(resps), out.String())
	}

	// 1) The blocked call returns a tool error (isError=true) mentioning a deadline.
	r1 := resps[0]["result"].(map[string]interface{})
	if r1["isError"] != true {
		t.Fatalf("blocked call should be isError, got: %v", resps[0])
	}
	txt := r1["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(strings.ToLower(txt), "deadline") && !strings.Contains(strings.ToLower(txt), "context") {
		t.Fatalf("blocked call error %q does not look like a timeout", txt)
	}

	// 2) The SECOND request was answered — the server is still responsive.
	r2 := resps[1]["result"].(map[string]interface{})
	if _, ok := r2["content"]; !ok {
		t.Fatalf("second request not answered (server wedged?): %v", resps[1])
	}

	// Sanity: total time is bounded by the budget, not infinite.
	if elapsed > 5*time.Second {
		t.Fatalf("Serve took %v — the timeout did not bound the hung call", elapsed)
	}
	t.Logf("hung call bounded by per-call timeout; server stayed responsive (elapsed %v)", elapsed)
}

// TestPerRequestCallCeiling is the MEDIUM-4 test: one tools/call cannot issue an
// unbounded number of eth_calls. With a small ceiling and a chain that would otherwise
// invite a deep scan, pending_operations bails with a ceiling error rather than hammering
// the upstream thousands of times.
func TestPerRequestCallCeiling(t *testing.T) {
	caller := &countingThoughtCaller{taskCount: 100000}
	srv := stubServer(t, caller)
	srv.maxCallsPerRequest = 8 // tiny ceiling for the test

	// pending_operations with a large limit would normally scan many tasks. The ceiling
	// must stop it well before taskCount.
	_, err := srv.CallTool(context.Background(), toolPendingOperations, map[string]interface{}{"limit": 200})
	if err == nil {
		t.Fatal("expected a per-request ceiling error, got nil")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("error %q is not the ceiling error", err.Error())
	}
	// The wrapper allows exactly `max` calls then fails the (max+1)th, so total calls is
	// bounded at max+1 — proving we did NOT run away to taskCount.
	if got := caller.calls.Load(); got > int64(srv.maxCallsPerRequest+1) {
		t.Fatalf("issued %d eth_calls, ceiling was %d — runaway not stopped", got, srv.maxCallsPerRequest)
	}
	t.Logf("call ceiling stopped the scan at %d eth_calls (max %d)", caller.calls.Load(), srv.maxCallsPerRequest)
}

// TestBoundedCallerForwardsUnderLimit proves the bounded caller is transparent below the
// ceiling (it must not break normal operation).
func TestBoundedCallerForwardsUnderLimit(t *testing.T) {
	caller := &countingThoughtCaller{taskCount: 3}
	bc := newBoundedCaller(caller, 100)
	for i := 0; i < 5; i++ {
		if _, err := bc.CallContract(context.Background(), gethereum.CallMsg{To: &common.Address{}}, nil); err != nil {
			t.Fatalf("call %d under the ceiling errored: %v", i, err)
		}
	}
	if got := bc.calls.Load(); got != 5 {
		t.Fatalf("bounded caller counted %d, want 5", got)
	}
}

// TestOversizedLineIsRejectedAndLoopSurvives is the HIGH-2 test: a request line larger
// than maxLineBytes must be rejected as a parse error WITHOUT buffering it whole, and the
// stdio loop must survive to answer the next (well-formed) request.
func TestOversizedLineIsRejectedAndLoopSurvives(t *testing.T) {
	srv := stubServer(t, blockingCaller{}) // chain_state needs no eth_call here

	// One oversized line (a JSON string padded past the cap) then a valid chain_state.
	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chain_state","arguments":{"pad":"` +
		strings.Repeat("A", maxLineBytes+1024) + `"}}}`
	valid := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"chain_state","arguments":{}}}`
	in := huge + "\n" + valid + "\n"

	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	resps := decodeLines(t, out.String())
	if len(resps) != 2 {
		t.Fatalf("want 2 responses (oversized parse error + valid result), got %d", len(resps))
	}
	// 1) Oversized line -> a JSON-RPC parse error (id null since we never parsed it).
	if resps[0]["error"] == nil {
		t.Fatalf("oversized line should yield a parse error, got: %v", resps[0])
	}
	em := resps[0]["error"].(map[string]interface{})
	if int(em["code"].(float64)) != codeParseError {
		t.Fatalf("oversized line error code=%v, want %d", em["code"], codeParseError)
	}
	// 2) The following valid request was still served.
	if _, ok := resps[1]["result"]; !ok {
		t.Fatalf("loop did not survive the oversized line: %v", resps[1])
	}
	t.Logf("oversized line rejected as parse error; loop survived and served the next request")
}

// TestReadLimitedLineDrainsAndResyncs unit-tests the bounded reader directly: an
// oversized line is reported tooLong with no buffered bytes, and the NEXT ReadByte starts
// on the following line (the reader drained to the newline).
func TestReadLimitedLineDrainsAndResyncs(t *testing.T) {
	const max = 16
	data := strings.Repeat("X", max*4) + "\n" + "ok\n"
	r := bufio.NewReader(strings.NewReader(data))

	line, tooLong, err := readLimitedLine(r, max)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !tooLong {
		t.Fatal("expected tooLong=true for the long line")
	}
	if len(line) != 0 {
		t.Fatalf("oversized line should return no buffered bytes, got %d", len(line))
	}
	// Next read returns the SECOND line intact.
	line2, tooLong2, err := readLimitedLine(r, max)
	if err != nil {
		t.Fatalf("unexpected err on line 2: %v", err)
	}
	if tooLong2 {
		t.Fatal("second line is short; tooLong must be false")
	}
	if strings.TrimSpace(string(line2)) != "ok" {
		t.Fatalf("after draining, next line=%q, want %q", strings.TrimSpace(string(line2)), "ok")
	}
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

// TestDispatchRecoversPanic is the LOW test: a handler panic becomes one isError tool
// result, not a whole-server crash. We register a panicking handler on a stub server.
func TestDispatchRecoversPanic(t *testing.T) {
	srv := stubServer(t, blockingCaller{})
	srv.tools["boom"] = func(_ *Server, _ context.Context, _ map[string]interface{}) (interface{}, error) {
		panic("kaboom")
	}
	_, err := srv.CallTool(context.Background(), "boom", nil)
	if err == nil {
		t.Fatal("expected a recovered-panic error, got nil")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("error %q is not the recovered-panic error", err.Error())
	}
	// And the server is still usable afterwards.
	if _, err := srv.CallTool(context.Background(), toolChainState, nil); err != nil {
		t.Fatalf("server unusable after recovered panic: %v", err)
	}
}

// ----------------------------------------------------------------------------
// helpers to synthesize ABI-encoded return values for the counting stub
// ----------------------------------------------------------------------------

// encodeUint256 returns the 32-byte big-endian encoding of v (an ABI uint256 return).
func encodeUint256(v *big.Int) []byte {
	return common.LeftPadBytes(v.Bytes(), 32)
}

// encodeOpenThought returns a minimally-valid ABI encoding of the AIGovernor Thought
// tuple with Status=Open. The tuple has two dynamic fields (knobKey string at the end is
// the only string; everything else is static within the head), so we hand-assemble the
// head + the string tail. We only need the unpacker to succeed and Status to read Open.
func encodeOpenThought() []byte {
	// The Thought tuple is a single dynamic struct return, so the outer return is one
	// offset word pointing at the tuple, then the tuple's own head, then its dynamic tail
	// (knobKey). Build it explicitly.
	zero32 := make([]byte, 32)
	word := func(n uint64) []byte { return common.LeftPadBytes(new(big.Int).SetUint64(n).Bytes(), 32) }

	// Tuple field layout (mirrors abi.go Thought / thoughtTuple), all padded to 32 bytes
	// in the tuple head; knobKey is dynamic so its head slot is an offset into the tuple.
	// Fields in order:
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

	// knobKey tail: offset is relative to the START of the tuple head. Empty string =
	// length 0 (one zero word).
	tupleHeadLen := uint64(len(head))
	copy(head[knobOffsetIdx:knobOffsetIdx+32], word(tupleHeadLen))
	tail := word(0) // string length 0

	tuple := append(head, tail...)

	// Outer return: one offset word (0x20) to the tuple.
	out := append(word(32), tuple...)
	return out
}
