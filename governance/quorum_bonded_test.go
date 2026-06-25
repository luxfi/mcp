// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
)

// deregister starts an operator's withdrawal cooldown (does NOT change the bond — the
// operator stays _bonded, so an already-cast verdict still counts at settle).
func (e *chainEnv) deregister(key *ecdsa.PrivateKey) {
	in, err := e.governor.abi.Pack("deregister")
	if err != nil {
		e.t.Fatalf("pack deregister: %v", err)
	}
	e.c.sendTx(addrOf(key), e.governor.addr, in, nil)
}

// withdrawBond zeroes an operator's bond (after the cooldown — the harness deploys with
// deregisterCooldown==0, so this succeeds immediately after deregister). A zero bond ⇒
// !_bonded ⇒ settle DROPS this operator's verdict.
func (e *chainEnv) withdrawBond(key *ecdsa.PrivateKey) {
	in, err := e.governor.abi.Pack("withdrawBond")
	if err != nil {
		e.t.Fatalf("pack withdrawBond: %v", err)
	}
	e.c.sendTx(addrOf(key), e.governor.addr, in, nil)
}

// onchainThoughtStatus reads the raw on-chain Status of a task directly (independent of
// MCP), so the test can compare MCP's prediction against the ACTUAL settle outcome.
func (e *chainEnv) onchainThoughtStatus(taskID *big.Int) uint8 {
	th := readStruct[Thought](e.t, e.c, e.governor, "getThought", taskID)
	return th.Status
}

// TestQuorumStatusMatchesSettleAfterWithdrawRace is the HIGH-1 PoC, made green.
//
// Red's exploit: N operators vote to form a quorum, then enough of them withdraw their
// bond that the operators STILL bonded at settle time fall below threshold. The old
// tallyQuorum counted EVERY verdict, so quorum_status reported quorumReached=true — but
// AIGovernor.settle() counts ONLY bonded operators (see _bonded) and therefore settles
// the task FAILED (NoQuorum). An operator-LLM trusting quorum_status would sign a
// concurring verdict for a quorum that does not exist on-chain.
//
// The fix re-derives the tally under the SAME bonded predicate settle uses (bond != 0 &&
// bond >= minBond, ignoring the deregister flag) at the observed block. This test proves
// quorum_status.quorumReached now MATCHES the real settle outcome in three scenarios:
//   - all operators bonded            -> quorum stands, settle Settled
//   - enough withdraw to drop quorum  -> quorum gone,  settle Failed (NoQuorum)
//   - deregistered but STILL bonded   -> verdict still counts (matches _bonded exactly)
func TestQuorumStatusMatchesSettleAfterWithdrawRace(t *testing.T) {
	// --- Scenario A: withdrawals drop the bonded set below threshold -> NoQuorum ---
	t.Run("withdraw_drops_below_threshold", func(t *testing.T) {
		ops := genKeys(t, 3) // threshold = 3/2+1 = 2
		_, env := newEVMChain(t, ops)
		srv := env.mcpServer()

		spec := specHash("upgrade-proposal-withdraw")
		knobKey := "approve-upgrade-withdraw"
		n := uint8(len(ops))
		for _, k := range ops {
			env.registerOperator(k)
		}
		taskID := env.openThought(spec, knobKey, n)

		// All three vote YES @ the SAME bucket -> one group of 3 (well over threshold 2).
		for _, k := range ops {
			env.submitVerdict(k, taskID, spec, voteYes, 10000)
		}

		// BEFORE any withdrawal, MCP must see a real quorum (sanity: the fix didn't break
		// the honest case).
		qBefore := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
		if qBefore["quorumReached"] != true {
			t.Fatalf("pre-withdraw quorumReached=%v, want true", qBefore["quorumReached"])
		}
		if got := toInt(t, qBefore["verdictsCounted"]); got != 3 {
			t.Fatalf("pre-withdraw verdictsCounted=%d, want 3", got)
		}

		// THE RACE: two of the three operators deregister + withdraw their bond. Their
		// verdicts are still in getVerdicts(), but they are no longer _bonded, so settle
		// drops them. Bonded YES group is now 1 < threshold 2.
		for _, k := range ops[:2] {
			env.deregister(k)
			env.withdrawBond(k)
		}

		// MCP quorum_status must now report quorumReached=FALSE (matching settle), and
		// account for the two dropped verdicts.
		q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
		if q["quorumReached"] != false {
			t.Fatalf("post-withdraw quorumReached=%v, want false (settle will drop unbonded verdicts)", q["quorumReached"])
		}
		if got := toInt(t, q["verdictsTotal"]); got != 3 {
			t.Fatalf("verdictsTotal=%d, want 3 (all verdicts still on-chain)", got)
		}
		if got := toInt(t, q["verdictsCounted"]); got != 1 {
			t.Fatalf("verdictsCounted=%d, want 1 (only the still-bonded operator)", got)
		}
		if got := toInt(t, q["droppedUnbonded"]); got != 2 {
			t.Fatalf("droppedUnbonded=%d, want 2", got)
		}
		if got := toInt(t, q["bestGroup"]); got != 1 {
			t.Fatalf("bestGroup=%d, want 1 (bonded YES group)", got)
		}

		// Now ACTUALLY settle on-chain (past the deadline) and prove the chain agrees:
		// the task settles FAILED (NoQuorum), exactly what MCP predicted.
		env.c.advanceSeconds(2 * 3600)
		env.settleThought(taskID)
		if got := env.onchainThoughtStatus(taskID); got != statusFailed {
			t.Fatalf("on-chain settle status=%d, want Failed(%d) — MCP predicted NoQuorum", got, statusFailed)
		}

		// And thought_status now reads NoQuorum, consistent with the prediction.
		ts := callTool(t, srv, toolThoughtStatus, map[string]interface{}{"taskId": taskID.String()})
		if ts["status"] != "NoQuorum" {
			t.Fatalf("thought_status=%v, want NoQuorum", ts["status"])
		}
	})

	// --- Scenario B: nobody withdraws -> quorum stands -> Settled ---
	t.Run("all_bonded_quorum_stands", func(t *testing.T) {
		ops := genKeys(t, 3)
		_, env := newEVMChain(t, ops)
		srv := env.mcpServer()

		spec := specHash("upgrade-proposal-stands")
		knobKey := "approve-upgrade-stands"
		n := uint8(len(ops))
		for _, k := range ops {
			env.registerOperator(k)
		}
		taskID := env.openThought(spec, knobKey, n)
		for _, k := range ops {
			env.submitVerdict(k, taskID, spec, voteYes, 10000)
		}

		q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
		if q["quorumReached"] != true {
			t.Fatalf("quorumReached=%v, want true", q["quorumReached"])
		}
		if got := toInt(t, q["droppedUnbonded"]); got != 0 {
			t.Fatalf("droppedUnbonded=%d, want 0", got)
		}

		env.c.advanceSeconds(2 * 3600)
		env.settleThought(taskID)
		if got := env.onchainThoughtStatus(taskID); got != statusSettled {
			t.Fatalf("on-chain settle status=%d, want Settled(%d)", got, statusSettled)
		}
	})

	// --- Scenario C: deregistered but STILL bonded -> verdict counts (matches _bonded) ---
	// This is the nuance red flagged: settle uses _bonded (bond floor only), NOT _eligible
	// (which also checks deregisterAt). A deregistered-but-bonded operator's verdict MUST
	// still count. If we wrongly excluded deregistered operators, this quorum would vanish.
	t.Run("deregistered_but_bonded_still_counts", func(t *testing.T) {
		ops := genKeys(t, 3)
		_, env := newEVMChain(t, ops)
		srv := env.mcpServer()

		spec := specHash("upgrade-proposal-dereg")
		knobKey := "approve-upgrade-dereg"
		n := uint8(len(ops))
		for _, k := range ops {
			env.registerOperator(k)
		}
		taskID := env.openThought(spec, knobKey, n)
		for _, k := range ops {
			env.submitVerdict(k, taskID, spec, voteYes, 10000)
		}

		// Two operators DEREGISTER but do NOT withdraw — bond stays at risk, so _bonded is
		// still true and their verdicts count. (deregisterCooldown==0 here, but we simply
		// never call withdrawBond.)
		for _, k := range ops[:2] {
			env.deregister(k)
		}

		q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
		if got := toInt(t, q["verdictsCounted"]); got != 3 {
			t.Fatalf("verdictsCounted=%d, want 3 (deregistered-but-bonded verdicts still count)", got)
		}
		if got := toInt(t, q["droppedUnbonded"]); got != 0 {
			t.Fatalf("droppedUnbonded=%d, want 0 (no bond was withdrawn)", got)
		}
		if q["quorumReached"] != true {
			t.Fatalf("quorumReached=%v, want true (3 bonded YES >= threshold 2)", q["quorumReached"])
		}

		// Chain confirms: a deregistered-but-bonded committee still settles to a quorum.
		env.c.advanceSeconds(2 * 3600)
		env.settleThought(taskID)
		if got := env.onchainThoughtStatus(taskID); got != statusSettled {
			t.Fatalf("on-chain settle status=%d, want Settled(%d) — deregistered-but-bonded must count", got, statusSettled)
		}
	})
}

// TestQuorumStatusWinningVoteForNonApproval is the MEDIUM-6 winning-vote test: a quorum
// can form around a NON-Yes vote (e.g. No). quorum_status must surface the winning vote
// so an LLM does not read "quorumReached=true" as "approved". Here the committee reaches
// a NO quorum: quorumReached is true, but winningVote is No and winningIsApprove false.
func TestQuorumStatusWinningVoteForNonApproval(t *testing.T) {
	ops := genKeys(t, 3) // threshold 2
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()

	spec := specHash("reject-upgrade-9")
	knobKey := "approve-upgrade-9"
	n := uint8(len(ops))
	for _, k := range ops {
		env.registerOperator(k)
	}
	taskID := env.openThought(spec, knobKey, n)

	// Two vote NO @ bucket 10000 (a NO quorum of 2 >= threshold 2); the third votes YES.
	env.submitVerdict(ops[0], taskID, spec, voteNo, 10000)
	env.submitVerdict(ops[1], taskID, spec, voteNo, 10000)
	env.submitVerdict(ops[2], taskID, spec, voteYes, 10000)

	q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
	if q["quorumReached"] != true {
		t.Fatalf("quorumReached=%v, want true (NO group of 2 >= threshold 2)", q["quorumReached"])
	}
	if got := toUint8(t, q["winningVote"]); got != voteNo {
		t.Fatalf("winningVote=%d, want No(%d)", got, voteNo)
	}
	if q["winningVoteLabel"] != "No" {
		t.Fatalf("winningVoteLabel=%v, want No", q["winningVoteLabel"])
	}
	if q["winningIsApprove"] != false {
		t.Fatalf("winningIsApprove=%v, want false (a No quorum is NOT an approval)", q["winningIsApprove"])
	}
	if got := toInt(t, q["votesAgainst"]); got != 2 {
		t.Fatalf("votesAgainst=%d, want 2", got)
	}
	if got := toInt(t, q["votesFor"]); got != 1 {
		t.Fatalf("votesFor=%d, want 1", got)
	}

	// Settle on-chain and confirm the winning vote MCP reported matches the canonical
	// vote the chain recorded (settle decodes the same best key).
	env.c.advanceSeconds(2 * 3600)
	env.settleThought(taskID)
	onchain := readStruct[Thought](t, env.c, env.governor, "getThought", taskID)
	if onchain.Status != statusSettled {
		t.Fatalf("on-chain status=%d, want Settled (a NO quorum settles)", onchain.Status)
	}
	if onchain.CanonicalVote != voteNo {
		t.Fatalf("on-chain canonicalVote=%d, want No(%d)", onchain.CanonicalVote, voteNo)
	}
	if got := toUint8(t, q["winningVote"]); got != onchain.CanonicalVote {
		t.Fatalf("MCP winningVote=%d != on-chain canonicalVote=%d", got, onchain.CanonicalVote)
	}
}

// TestQuorumStatusDeadlineGate is the MEDIUM-6 deadline test: mid-window, a reached
// quorum is NOT yet settleable (settle reverts before the deadline). quorum_status must
// label this: quorumReached can be true while settleable is false and deadlinePassed is
// false. After the deadline passes, settleable flips true.
func TestQuorumStatusDeadlineGate(t *testing.T) {
	ops := genKeys(t, 3)
	_, env := newEVMChain(t, ops)
	srv := env.mcpServer()

	spec := specHash("deadline-gate-task")
	knobKey := "approve-deadline-gate"
	n := uint8(len(ops))
	for _, k := range ops {
		env.registerOperator(k)
	}
	taskID := env.openThought(spec, knobKey, n)
	for _, k := range ops {
		env.submitVerdict(k, taskID, spec, voteYes, 10000)
	}

	// Mid-window: quorum reached, but the deadline has NOT passed -> not settleable.
	q := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
	if q["quorumReached"] != true {
		t.Fatalf("quorumReached=%v, want true", q["quorumReached"])
	}
	if q["deadlinePassed"] != false {
		t.Fatalf("deadlinePassed=%v, want false (still mid-window)", q["deadlinePassed"])
	}
	if q["settleable"] != false {
		t.Fatalf("settleable=%v, want false mid-window (settle reverts before deadline)", q["settleable"])
	}

	// Advance past the 1h voting window; now the quorum is settleable.
	env.c.advanceSeconds(2 * 3600)
	q2 := callTool(t, srv, toolQuorumStatus, map[string]interface{}{"taskId": taskID.String()})
	if q2["deadlinePassed"] != true {
		t.Fatalf("deadlinePassed=%v, want true after the window", q2["deadlinePassed"])
	}
	if q2["settleable"] != true {
		t.Fatalf("settleable=%v, want true after deadline with quorum", q2["settleable"])
	}

	// And the chain agrees it can settle now.
	env.settleThought(taskID)
	if got := env.onchainThoughtStatus(taskID); got != statusSettled {
		t.Fatalf("on-chain status=%d, want Settled", got)
	}
}
