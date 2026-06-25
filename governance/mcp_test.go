// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/mcp"
)

// callTool runs a read tool and returns its result as a map (all tool results are
// JSON objects). Fails the test on tool error or wrong shape.
func callTool(t *testing.T, srv *mcp.Server, name string, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	res, err := srv.CallTool(context.Background(), name, args)
	if err != nil {
		t.Fatalf("tool %s: %v", name, err)
	}
	m, ok := res.(map[string]interface{})
	if !ok {
		t.Fatalf("tool %s: result not a map: %T", name, res)
	}
	return m
}

// driveSettledRound registers `n` operators, opens a round, fills all n slots with
// the SAME value (so the median is deterministic), and settles it. Returns the
// roundId, the spec, the knobKey, and the decided value. n is the committee size and
// equals the operator population, so every operator is sampled (size>=population).
func driveSettledRound(t *testing.T, env *chainEnv, ops []*ecdsa.PrivateKey, value *big.Int) (*big.Int, [32]byte, string) {
	t.Helper()
	spec := specHash("zen-nano-temperature")
	knobKey := "temperature"
	n := uint8(len(ops))

	for _, k := range ops {
		env.registerOperator(k)
	}
	roundID := env.openRound(spec, knobKey, big.NewInt(0), big.NewInt(1000), n)
	// Seed = blockhash(openBlock) is only available from openBlock+1, so mine one
	// empty block before the first proposal.
	env.c.advanceBlocks(1)
	for _, k := range ops {
		env.submitProposal(k, roundID, spec, value, 5000)
	}
	// All n slots filled ⇒ settle is allowed before the deadline.
	env.settleRound(roundID)
	return roundID, spec, knobKey
}

// TestLiveParamRoundSetsAIParamsValue drives a full AIParams round on the deployed
// contract (open → operators propose → settle) and asserts param_value (MCP) reads
// back the newly-decided value equal to the on-chain valueOf.
func TestLiveParamRoundSetsAIParamsValue(t *testing.T) {
	ops := genKeys(t, 3)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()

	value := big.NewInt(420)

	// Before the round settles, the knob is not decided.
	specPre := specHash("zen-nano-temperature")
	pre := callTool(t, srv, toolParamValue, map[string]interface{}{
		"modelSpecHash": common.BytesToHash(specPre[:]).Hex(),
		"knobKey":       "temperature",
	})
	if pre["decided"] != false {
		t.Fatalf("expected decided=false before round, got %v", pre["decided"])
	}

	_, spec, knobKey := driveSettledRound(t, env, ops, value)

	// MCP param_value must now reflect the decided value.
	got := callTool(t, srv, toolParamValue, map[string]interface{}{
		"modelSpecHash": common.BytesToHash(spec[:]).Hex(),
		"knobKey":       knobKey,
	})
	if got["decided"] != true {
		t.Fatalf("param_value decided=%v, want true", got["decided"])
	}
	if got["value"] != value.String() {
		t.Fatalf("param_value value=%v, want %s", got["value"], value.String())
	}

	// Cross-check directly against the on-chain valueOf (independent of MCP).
	out := env.callParams("valueOf", spec, knobKey)
	onchainValue := out[0].(*big.Int)
	onchainDecided := out[1].(bool)
	if !onchainDecided || onchainValue.Cmp(value) != 0 {
		t.Fatalf("on-chain valueOf=(%s,%v), want (%s,true)", onchainValue, onchainDecided, value)
	}
	if got["value"] != onchainValue.String() {
		t.Fatalf("MCP value %v != on-chain value %s", got["value"], onchainValue)
	}
}

// TestMCPParamHistoryMatchesAIParams asserts param_history output equals what
// AIParams.roundCount/getRound/getProposals return for the same rounds (field parity).
func TestMCPParamHistoryMatchesAIParams(t *testing.T) {
	ops := genKeys(t, 3)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()

	_, spec, knobKey := driveSettledRound(t, env, ops, big.NewInt(777))

	hist := callTool(t, srv, toolParamHistory, map[string]interface{}{})

	// roundCount parity.
	rcOut := env.callParams("roundCount")
	wantCount := rcOut[0].(*big.Int)
	if hist["roundCount"] != wantCount.String() {
		t.Fatalf("param_history roundCount=%v, want %s", hist["roundCount"], wantCount)
	}

	rounds, ok := hist["rounds"].([]interface{})
	if !ok || len(rounds) == 0 {
		t.Fatalf("param_history returned no rounds: %v", hist["rounds"])
	}

	// The newest round (index 0, descending) is roundId wantCount-1. Field parity
	// against the on-chain getRound.
	first := rounds[0].(map[string]interface{})
	roundID := new(big.Int).Sub(wantCount, big.NewInt(1))
	if first["roundId"] != roundID.String() {
		t.Fatalf("first round id=%v, want %s", first["roundId"], roundID)
	}

	onchain := readStruct[Round](t, env.c, env.params, "getRound", roundID)
	rj := first["round"].(map[string]interface{})
	if rj["knobKey"] != onchain.KnobKey || onchain.KnobKey != knobKey {
		t.Fatalf("knobKey mismatch: mcp=%v onchain=%v want=%s", rj["knobKey"], onchain.KnobKey, knobKey)
	}
	if rj["modelSpecHash"] != common.BytesToHash(spec[:]).Hex() {
		t.Fatalf("modelSpecHash mismatch: %v", rj["modelSpecHash"])
	}
	if rj["canonicalValue"] != onchain.CanonicalValue.String() {
		t.Fatalf("canonicalValue mismatch: mcp=%v onchain=%s", rj["canonicalValue"], onchain.CanonicalValue)
	}
	if got := toUint8(t, rj["submissionCount"]); got != onchain.SubmissionCount {
		t.Fatalf("submissionCount mismatch: mcp=%d onchain=%d", got, onchain.SubmissionCount)
	}
	if got := toUint8(t, rj["status"]); got != onchain.Status {
		t.Fatalf("status mismatch: mcp=%d onchain=%d", got, onchain.Status)
	}

	// Proposals parity: count and each value/operator.
	onProps := readStruct[[]Proposal](t, env.c, env.params, "getProposals", roundID)
	mcpProps := first["proposals"].([]interface{})
	if len(mcpProps) != len(onProps) {
		t.Fatalf("proposals count mismatch: mcp=%d onchain=%d", len(mcpProps), len(onProps))
	}
	for i := range onProps {
		p := mcpProps[i].(map[string]interface{})
		if p["value"] != onProps[i].Value.String() {
			t.Errorf("proposal[%d] value: mcp=%v onchain=%s", i, p["value"], onProps[i].Value)
		}
		if p["operator"] != onProps[i].Operator.Hex() {
			t.Errorf("proposal[%d] operator: mcp=%v onchain=%s", i, p["operator"], onProps[i].Operator.Hex())
		}
	}
}

// TestMCPThoughtStatusMatchesAIGovernor asserts thought_status fields equal
// AIGovernor.getThought for the same taskId, and the derived status matches the
// contract's open/settled/quorum semantics.
func TestMCPThoughtStatusMatchesAIGovernor(t *testing.T) {
	ops := genKeys(t, 3)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()

	spec := specHash("upgrade-proposal-7")
	knobKey := "approve-upgrade-7"
	n := uint8(len(ops))
	for _, k := range ops {
		env.registerOperator(k)
	}
	taskID := env.openThought(spec, knobKey, n)

	// While Open: derived status must be "Open".
	openRes := callTool(t, srv, toolThoughtStatus, map[string]interface{}{"taskId": taskID.String()})
	if openRes["status"] != "Open" {
		t.Fatalf("open thought status=%v, want Open", openRes["status"])
	}

	// All operators vote YES @ bucket 10000 (unanimous ⇒ quorum on settle).
	for _, k := range ops {
		env.submitVerdict(k, taskID, spec, voteYes, 10000)
	}
	// Committee full (submissionCount==n) but settle needs the deadline; advance time.
	env.c.advanceSeconds(2 * 3600) // past the 1h voting window
	env.settleThought(taskID)

	res := callTool(t, srv, toolThoughtStatus, map[string]interface{}{"taskId": taskID.String()})

	onchain := readStruct[Thought](t, env.c, env.governor, "getThought", taskID)

	// Field parity.
	if res["modelSpecHash"] != common.BytesToHash(onchain.ModelSpecHash[:]).Hex() {
		t.Fatalf("modelSpecHash mismatch: %v", res["modelSpecHash"])
	}
	if res["knobKey"] != onchain.KnobKey {
		t.Fatalf("knobKey mismatch: mcp=%v onchain=%v", res["knobKey"], onchain.KnobKey)
	}
	if got := toUint8(t, res["threshold"]); got != onchain.Threshold {
		t.Fatalf("threshold mismatch: mcp=%d onchain=%d", got, onchain.Threshold)
	}
	if got := toUint8(t, res["n"]); got != onchain.N {
		t.Fatalf("n mismatch: mcp=%d onchain=%d", got, onchain.N)
	}
	if got := toUint8(t, res["agreeCount"]); got != onchain.AgreeCount {
		t.Fatalf("agreeCount mismatch: mcp=%d onchain=%d", got, onchain.AgreeCount)
	}
	if got := toUint8(t, res["canonicalVote"]); got != onchain.CanonicalVote {
		t.Fatalf("canonicalVote mismatch: mcp=%d onchain=%d", got, onchain.CanonicalVote)
	}

	// Derived status semantics: a YES-quorum settle ⇒ Settled, status==2.
	if onchain.Status != statusSettled {
		t.Fatalf("expected on-chain Settled (2), got %d", onchain.Status)
	}
	if res["status"] != "Settled" {
		t.Fatalf("derived status=%v, want Settled", res["status"])
	}

	// taskCount parity.
	tcOut := env.c.callViewValues(env.governor, "taskCount")
	if res["taskCount"] != tcOut[0].(*big.Int).String() {
		t.Fatalf("taskCount mismatch: mcp=%v onchain=%v", res["taskCount"], tcOut[0])
	}

	// quorum_status cross-check: unanimous YES means votesFor==n, quorumReached.
	q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
	if got := toInt(t, q["votesFor"]); got != int(n) {
		t.Fatalf("quorum votesFor=%d, want %d", got, n)
	}
	if q["quorumReached"] != true {
		t.Fatalf("quorumReached=%v, want true", q["quorumReached"])
	}
}

// TestOperatorVerdictBindsMCPObservedState constructs a ChainObservation from tool
// reads, hashes it, embeds the hash in a mock verdict, and proves the verdict's bound
// observation-hash re-derives from re-reading the chain — i.e. a verdict can be
// checked against the state it claims to have observed.
func TestOperatorVerdictBindsMCPObservedState(t *testing.T) {
	ops := genKeys(t, 3)
	_, env := newEVMChain(t, ops)
	g := env.mcpSurface()

	_, spec, knobKey := driveSettledRound(t, env, ops, big.NewInt(333))

	// 1. The operator reads the decided knob via the governance surface and pins it into
	//    an observation built by the shared mcp package.
	value, decided, err := g.readParamValue(context.Background(), env.c, spec, knobKey)
	if err != nil {
		t.Fatalf("readParamValue: %v", err)
	}
	obs1, err := mcp.NewObservation(context.Background(), env.c, toolParamValue, []mcp.ObservedFact{
		{Key: "knobKey", Value: knobKey},
		{Key: "value", Value: value.String()},
		{Key: "decided", Value: boolStr(decided)},
	})
	if err != nil {
		t.Fatalf("NewObservation: %v", err)
	}
	boundHash := obs1.Hash()

	// 2. A mock verdict embeds that observation hash as its evidence binding.
	verdict := mockVerdict{
		taskID:   big.NewInt(0),
		vote:     voteYes,
		obsBound: boundHash,
	}

	// 3. A checker RE-READS the same chain facts (no new block has been added) and
	//    re-derives the observation hash; it must equal what the verdict bound.
	value2, decided2, err := g.readParamValue(context.Background(), env.c, spec, knobKey)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	obs2, err := mcp.NewObservation(context.Background(), env.c, toolParamValue, []mcp.ObservedFact{
		// Deliberately a different append order to prove canonicalization sorts it.
		{Key: "value", Value: value2.String()},
		{Key: "decided", Value: boolStr(decided2)},
		{Key: "knobKey", Value: knobKey},
	})
	if err != nil {
		t.Fatalf("NewObservation re-read: %v", err)
	}
	rederived := obs2.Hash()

	if rederived != verdict.obsBound {
		t.Fatalf("verdict observation binding broken:\n  bound:     %s\n  rederived: %s", verdict.obsBound.Hex(), rederived.Hex())
	}

	// Canonical bytes must be byte-identical regardless of fact append order.
	if string(obs1.Canonical()) != string(obs2.Canonical()) {
		t.Fatalf("canonical serialization not order-independent:\n  %s\n  %s", obs1.Canonical(), obs2.Canonical())
	}

	// And a verdict claiming a DIFFERENT value must NOT match (binding is meaningful).
	tampered, _ := mcp.NewObservation(context.Background(), env.c, toolParamValue, []mcp.ObservedFact{
		{Key: "knobKey", Value: knobKey},
		{Key: "value", Value: "999999"}, // lie about the value
		{Key: "decided", Value: boolStr(decided)},
	})
	if tampered.Hash() == verdict.obsBound {
		t.Fatal("tampered observation hashed equal to the honest binding — hash is not binding")
	}
}

// TestStaleMCPObservationRejectedOrFlagged proves an observation taken at block N is
// detectably stale at block N+k: Verify flags/rejects when the chain advances past
// maxAgeBlocks, and rejects when the observed block's hash no longer matches (reorg).
func TestStaleMCPObservationRejectedOrFlagged(t *testing.T) {
	ops := genKeys(t, 1)
	_, env := newEVMChain(t, ops)

	// Observation at the current head.
	obs, err := mcp.NewObservation(context.Background(), env.c, toolChainState, nil)
	if err != nil {
		t.Fatalf("NewObservation: %v", err)
	}

	// Immediately, with zero tolerance, it is fresh.
	fresh, err := obs.Verify(context.Background(), env.c, 0)
	if err != nil || !fresh {
		t.Fatalf("fresh observation rejected at age 0: fresh=%v err=%v", fresh, err)
	}

	// Advance the chain by 3 blocks.
	env.c.advanceBlocks(3)

	// With zero tolerance it is now STALE.
	fresh, err = obs.Verify(context.Background(), env.c, 0)
	if fresh {
		t.Fatal("stale observation (3 blocks old) passed Verify with maxAge=0")
	}
	if err == nil {
		t.Fatal("expected a staleness error, got nil")
	}
	t.Logf("staleness correctly flagged: %v", err)

	// With a generous tolerance (>=3) the SAME observation is still acceptable,
	// because its block is still canonical (no reorg) — proving the check is age,
	// not just inequality.
	fresh, err = obs.Verify(context.Background(), env.c, 8)
	if err != nil || !fresh {
		t.Fatalf("observation within maxAge=8 wrongly rejected: fresh=%v err=%v", fresh, err)
	}

	// Reorg detection: forge an observation whose recorded blockHash is wrong for its
	// height. Verify must reject it even within the age window.
	bad := &mcp.ChainObservation{
		ChainID:     obs.ChainID,
		BlockNumber: obs.BlockNumber,
		BlockHash:   common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		Timestamp:   obs.Timestamp,
		Tool:        toolChainState,
	}
	fresh, err = bad.Verify(context.Background(), env.c, 1000)
	if fresh {
		t.Fatal("observation with a non-canonical blockHash passed Verify (reorg not detected)")
	}
	if err == nil {
		t.Fatal("expected a reorg error, got nil")
	}
	t.Logf("reorg correctly flagged: %v", err)
}

// ----------------------------------------------------------------------------
// test helpers
// ----------------------------------------------------------------------------

// mockVerdict stands in for the operator's signed verdict; the only field the MCP
// binding cares about is obsBound — the ChainObservation hash the operator commits.
type mockVerdict struct {
	taskID   *big.Int
	vote     uint8
	obsBound common.Hash
}

// toUint8 coerces a JSON-decoded numeric (uint8 from the tool, or float64 if it
// round-tripped through JSON) to uint8.
func toUint8(t *testing.T, v interface{}) uint8 {
	t.Helper()
	switch n := v.(type) {
	case uint8:
		return n
	case float64:
		return uint8(n)
	case int:
		return uint8(n)
	default:
		t.Fatalf("not a uint8-ish value: %T (%v)", v, v)
		return 0
	}
}

func toInt(t *testing.T, v interface{}) int {
	t.Helper()
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case uint8:
		return int(n)
	default:
		t.Fatalf("not an int-ish value: %T (%v)", v, v)
		return 0
	}
}
