// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"context"
	"fmt"
	"math/big"

	"github.com/luxfi/geth/common"
)

// The eight read tools — the entire v1 surface. Each reads chain facts via the
// server's read-only EthCaller (eth_call / header reads) and returns a
// JSON-serializable value. NONE writes; there is no tx-submitting path here.
const (
	toolChainState         = "chain_state"
	toolParamValue         = "param_value"
	toolParamHistory       = "param_history"
	toolThoughtStatus      = "thought_status"
	toolReceiptLookup      = "receipt_lookup"
	toolQuorumStatus       = "quorum_status"
	toolOperatorReputation = "operator_reputation"
	toolPendingOperations  = "pending_operations"
)

// Thought lifecycle status values (IAIGovernor.Status / AIParams.Status).
const (
	statusNone    uint8 = 0
	statusOpen    uint8 = 1
	statusSettled uint8 = 2
	statusFailed  uint8 = 3
)

// Vote values (IAIGovernor.Vote): invalid=0, yes=1, no=2, abstain=3, delay=4,
// unsafe=5. A settling group whose winning vote is anything other than Yes is NOT an
// approval — quorum_status surfaces the winning vote so an operator-LLM never reads a
// No/Unsafe/Delay quorum as a go-ahead.
const (
	voteInvalid uint8 = 0
	voteYes     uint8 = 1
	voteNo      uint8 = 2
	voteAbstain uint8 = 3
	voteDelay   uint8 = 4
	voteUnsafe  uint8 = 5
)

// voteLabel maps a Vote value to its IAIGovernor.Vote name (so a winning bucket reads
// as "Yes"/"No"/… and a reader cannot mistake a non-Yes quorum for an approval).
func voteLabel(v uint8) string {
	switch v {
	case voteYes:
		return "Yes"
	case voteNo:
		return "No"
	case voteAbstain:
		return "Abstain"
	case voteDelay:
		return "Delay"
	case voteUnsafe:
		return "Unsafe"
	default:
		return "Invalid"
	}
}

const defaultLimit = 16

// pendingScanFloor is the minimum number of tail tasks pending_operations inspects even
// when the caller's limit is tiny, so a just-opened task isn't missed behind a few
// freshly-settled ones. The per-request eth_call ceiling (see server.go) is the hard
// backstop against amplification; this only sizes the look-back window.
const pendingScanFloor = int64(64)

// registerTools builds the handler map and the descriptor list. The two are kept
// in lockstep so tools/list always matches what tools/call can dispatch.
func registerTools() (map[string]toolHandler, []Tool) {
	descs := []Tool{
		{
			Name:        toolChainState,
			Description: "Current chain head: block number, chain id, latest block hash and timestamp.",
			InputSchema: objSchema(nil, nil),
		},
		{
			Name:        toolParamValue,
			Description: "Read a decided governance knob value from AIParams.valueOf(modelSpecHash, knobKey). Returns {value, decided}.",
			InputSchema: objSchema(map[string]interface{}{
				"modelSpecHash": strSchema("bytes32 model spec hash, 0x-hex"),
				"knobKey":       strSchema("knob key string"),
			}, []string{"modelSpecHash", "knobKey"}),
		},
		{
			Name:        toolParamHistory,
			Description: "AIParams round history (newest first): each round with its proposals. Optional limit (default 16) and fromRound.",
			InputSchema: objSchema(map[string]interface{}{
				"limit":     intSchema("max rounds to return (default 16)"),
				"fromRound": intSchema("highest round id to start from (default roundCount-1)"),
			}, nil),
		},
		{
			Name:        toolThoughtStatus,
			Description: "AIGovernor.getThought(taskId) fields plus a derived status (Open/Settled/NoQuorum) and taskCount.",
			InputSchema: objSchema(map[string]interface{}{
				"taskId": intSchema("task id"),
			}, []string{"taskId"}),
		},
		{
			Name:        toolReceiptLookup,
			Description: "AIThoughtRegistry receipt lookup by receiptId. Returns {exists, receipt, receiptCount}.",
			InputSchema: objSchema(map[string]interface{}{
				"receiptId": strSchema("bytes32 receipt id, 0x-hex"),
			}, []string{"receiptId"}),
		},
		{
			Name: toolQuorumStatus,
			Description: "Quorum tally for a task, computed to match AIGovernor.settle() exactly. " +
				"Counts ONLY verdicts from operators still bonded at the observed block (a " +
				"withdrawn operator's verdict is dropped, as settle drops it), groups by " +
				"(vote,bucket), and reports quorumReached, the winningVote/winningBucket, " +
				"winningIsApprove (winning vote == Yes), deadlinePassed and settleable " +
				"(quorum reached AND deadline passed — settle reverts before the deadline). " +
				"Also returns verdictsTotal/verdictsCounted/droppedUnbonded and observedBlock.",
			InputSchema: objSchema(map[string]interface{}{
				"taskId": intSchema("task id"),
			}, []string{"taskId"}),
		},
		{
			Name:        toolOperatorReputation,
			Description: "Operator standing: {isOperator, bond, weight, agreementRateBps, rep} from AIGovernor and AIReputation.",
			InputSchema: objSchema(map[string]interface{}{
				"operator": strSchema("operator address, 0x-hex"),
			}, []string{"operator"}),
		},
		{
			Name: toolPendingOperations,
			Description: "Currently-OPEN (unsettled) thoughts. Optional limit (default 16). Scans only the " +
				"TAIL of taskCount (newest tasks), so a still-Open task buried below the window is " +
				"NOT returned; when that happens truncated=true and scannedFrom marks the lowest id " +
				"inspected (range scannedFrom..taskCount-1). Each entry carries deadlinePassed " +
				"(now >= deadline) so a still-Open task whose voting window has closed is visible as " +
				"settle-ready. Also returns observedBlock.",
			InputSchema: objSchema(map[string]interface{}{
				"limit": intSchema("max open thoughts to return (default 16)"),
			}, nil),
		},
	}
	handlers := map[string]toolHandler{
		toolChainState:         (*Server).toolChainState,
		toolParamValue:         (*Server).toolParamValue,
		toolParamHistory:       (*Server).toolParamHistory,
		toolThoughtStatus:      (*Server).toolThoughtStatus,
		toolReceiptLookup:      (*Server).toolReceiptLookup,
		toolQuorumStatus:       (*Server).toolQuorumStatus,
		toolOperatorReputation: (*Server).toolOperatorReputation,
		toolPendingOperations:  (*Server).toolPendingOperations,
	}
	return handlers, descs
}

// ----------------------------------------------------------------------------
// 1. chain_state
// ----------------------------------------------------------------------------

func (s *Server) toolChainState(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	chainID, err := s.ec.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain_state: chainID: %w", err)
	}
	bn, err := s.ec.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain_state: blockNumber: %w", err)
	}
	hdr, err := s.ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("chain_state: header: %w", err)
	}
	return map[string]interface{}{
		"chainId":     chainID.String(),
		"blockNumber": bn,
		"blockHash":   hdr.Hash().Hex(),
		"timestamp":   hdr.Time,
	}, nil
}

// ----------------------------------------------------------------------------
// 2. param_value
// ----------------------------------------------------------------------------

func (s *Server) toolParamValue(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	spec, err := argBytes32(args, "modelSpecHash")
	if err != nil {
		return nil, err
	}
	key, err := argString(args, "knobKey")
	if err != nil {
		return nil, err
	}
	value, decided, err := s.readParamValue(ctx, spec, key)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"value":   value.String(),
		"decided": decided,
	}, nil
}

// readParamValue is the shared AIParams.valueOf read (used by the tool and tests).
func (s *Server) readParamValue(ctx context.Context, spec [32]byte, key string) (*big.Int, bool, error) {
	out, err := s.params.call(ctx, s.ec, "valueOf", spec, key)
	if err != nil {
		return nil, false, err
	}
	if len(out) != 2 {
		return nil, false, fmt.Errorf("param_value: valueOf returned %d values", len(out))
	}
	value, ok := out[0].(*big.Int)
	if !ok {
		return nil, false, fmt.Errorf("param_value: value not *big.Int")
	}
	decided, ok := out[1].(bool)
	if !ok {
		return nil, false, fmt.Errorf("param_value: decided not bool")
	}
	return value, decided, nil
}

// ----------------------------------------------------------------------------
// 3. param_history
// ----------------------------------------------------------------------------

func (s *Server) toolParamHistory(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := argLimit(args, defaultLimit)
	count, err := s.readRoundCount(ctx)
	if err != nil {
		return nil, err
	}
	rounds, err := s.readParamHistory(ctx, count, argFromRound(args, count), limit)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"roundCount": count.String(),
		"rounds":     rounds,
	}, nil
}

func (s *Server) readRoundCount(ctx context.Context) (*big.Int, error) {
	out, err := s.params.call(ctx, s.ec, "roundCount")
	if err != nil {
		return nil, err
	}
	c, ok := out[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("param_history: roundCount not *big.Int")
	}
	return c, nil
}

// readParamHistory walks rounds DESCENDING from `from` (inclusive), capped at limit,
// returning each round's fields and its proposals. `from` defaults to count-1 when
// not supplied by the caller; rounds beyond count-1 are clamped.
func (s *Server) readParamHistory(ctx context.Context, count, from *big.Int, limit int) ([]interface{}, error) {
	out := []interface{}{}
	if count.Sign() == 0 {
		return out, nil
	}
	last := new(big.Int).Sub(count, big.NewInt(1))
	start := from
	if start == nil || start.Cmp(last) > 0 {
		start = last
	}
	for i := new(big.Int).Set(start); i.Sign() >= 0 && len(out) < limit; i.Sub(i, big.NewInt(1)) {
		round, err := s.readRound(ctx, i)
		if err != nil {
			return nil, err
		}
		proposals, err := s.readProposals(ctx, i)
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"roundId":   new(big.Int).Set(i).String(),
			"round":     roundJSON(round),
			"proposals": proposalsJSON(proposals),
		})
	}
	return out, nil
}

func (s *Server) readRound(ctx context.Context, roundID *big.Int) (*Round, error) {
	r, err := callStruct[Round](ctx, s.params, s.ec, "getRound", roundID)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Server) readProposals(ctx context.Context, roundID *big.Int) ([]Proposal, error) {
	return callStruct[[]Proposal](ctx, s.params, s.ec, "getProposals", roundID)
}

// ----------------------------------------------------------------------------
// 4. thought_status
// ----------------------------------------------------------------------------

func (s *Server) toolThoughtStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	taskID, err := argUint256(args, "taskId")
	if err != nil {
		return nil, err
	}
	t, err := s.readThought(ctx, taskID)
	if err != nil {
		return nil, err
	}
	count, err := s.readTaskCount(ctx)
	if err != nil {
		return nil, err
	}
	res := thoughtJSON(t)
	res["status"] = derivedStatus(t.Status)
	res["taskCount"] = count.String()
	return res, nil
}

func (s *Server) readThought(ctx context.Context, taskID *big.Int) (*Thought, error) {
	return s.readThoughtAt(ctx, nil, taskID)
}

func (s *Server) readTaskCount(ctx context.Context) (*big.Int, error) {
	return s.readTaskCountAt(ctx, nil)
}

// derivedStatus maps the on-chain Status to the operator-facing label. The chain's
// settle() moves a task Open->Settled on quorum or Open->Failed on no-quorum, so the
// derived label is: Open while accepting verdicts, Settled on quorum, NoQuorum on a
// Failed settle (the task ran but no group reached threshold). None = nonexistent.
func derivedStatus(status uint8) string {
	switch status {
	case statusOpen:
		return "Open"
	case statusSettled:
		return "Settled"
	case statusFailed:
		return "NoQuorum"
	default:
		return "None"
	}
}

// ----------------------------------------------------------------------------
// 5. receipt_lookup
// ----------------------------------------------------------------------------

func (s *Server) toolReceiptLookup(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id, err := argBytes32(args, "receiptId")
	if err != nil {
		return nil, err
	}
	existsOut, err := s.registry.call(ctx, s.ec, "exists", id)
	if err != nil {
		return nil, err
	}
	exists, ok := existsOut[0].(bool)
	if !ok {
		return nil, fmt.Errorf("receipt_lookup: exists not bool")
	}
	countOut, err := s.registry.call(ctx, s.ec, "receiptCount")
	if err != nil {
		return nil, err
	}
	count, ok := countOut[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("receipt_lookup: receiptCount not *big.Int")
	}
	res := map[string]interface{}{
		"exists":       exists,
		"receiptCount": count.String(),
	}
	if exists {
		rc, err := callStruct[ThoughtReceipt](ctx, s.registry, s.ec, "getReceipt", id)
		if err != nil {
			return nil, err
		}
		res["receipt"] = receiptJSON(&rc)
	}
	return res, nil
}

// ----------------------------------------------------------------------------
// 6. quorum_status
// ----------------------------------------------------------------------------

func (s *Server) toolQuorumStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	taskID, err := argUint256(args, "taskId")
	if err != nil {
		return nil, err
	}
	// Pin every read of this tally to ONE block. settle() decides quorum from the
	// operators bonded AT settle time; if we read the verdicts at block N but the bonds
	// at a later head, an operator that withdrew in between could be counted (or not)
	// inconsistently. Reading thought, verdicts and bonds all at `block` gives a single
	// settle-equivalent snapshot and closes that withdraw race.
	block, err := s.observedBlock(ctx)
	if err != nil {
		return nil, err
	}
	now, err := s.blockTimestamp(ctx, block)
	if err != nil {
		return nil, err
	}
	t, err := s.readThoughtAt(ctx, block, taskID)
	if err != nil {
		return nil, err
	}
	verdicts, err := s.readVerdictsAt(ctx, block, taskID)
	if err != nil {
		return nil, err
	}
	minBond, err := s.readMinBond(ctx, block)
	if err != nil {
		return nil, err
	}
	bonded, err := s.readBondedSet(ctx, block, verdicts, minBond)
	if err != nil {
		return nil, err
	}
	tally := tallyQuorum(verdicts, t.Threshold, bonded)

	// settle()'s liveness gate is `block.timestamp < deadline -> revert` (AIGovernor.sol
	// settle, the only gate — there is no full-committee early exit in the code path).
	// So a quorum is only ACTUALLY settleable once the deadline has passed.
	deadlinePassed := now >= t.Deadline
	return map[string]interface{}{
		"verdicts":         verdictsJSON(verdicts),
		"threshold":        t.Threshold,
		"deadline":         t.Deadline,
		"votesFor":         tally.votesFor,
		"votesAgainst":     tally.votesAgainst,
		"quorumReached":    tally.quorumReached,
		"bestGroup":        tally.bestCount,
		"winningVote":      tally.winningVote,
		"winningVoteLabel": voteLabel(tally.winningVote),
		"winningBucket":    tally.winningBucket,
		"winningIsApprove": tally.quorumReached && tally.winningVote == voteYes,
		"deadlinePassed":   deadlinePassed,
		// settleable mirrors what settle() will accept right now: a reached quorum whose
		// deadline has passed. Mid-window a reached quorum is NOT yet settleable.
		"settleable":      tally.quorumReached && deadlinePassed,
		"verdictsTotal":   len(verdicts),
		"verdictsCounted": tally.counted,
		"droppedUnbonded": len(verdicts) - tally.counted,
		"observedBlock":   block.String(),
	}, nil
}

func (s *Server) readVerdictsAt(ctx context.Context, block, taskID *big.Int) ([]Verdict, error) {
	return callStructAt[[]Verdict](ctx, s.governor, s.ec, block, "getVerdicts", taskID)
}

func (s *Server) readThoughtAt(ctx context.Context, block, taskID *big.Int) (*Thought, error) {
	t, err := callStructAt[Thought](ctx, s.governor, s.ec, block, "getThought", taskID)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// readMinBond reads AIGovernor.minBond() at `block` — the bonded-eligibility floor
// settle() applies (see _bonded).
func (s *Server) readMinBond(ctx context.Context, block *big.Int) (*big.Int, error) {
	out, err := s.governor.callAt(ctx, s.ec, block, "minBond")
	if err != nil {
		return nil, err
	}
	mb, ok := out[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("quorum_status: minBond not *big.Int")
	}
	return mb, nil
}

// readBondedSet returns the set of verdict operators that are BONDED at `block` under
// the contract's exact settle predicate: AIGovernor._bonded(who) == (bondOf(who) != 0
// && bondOf(who) >= minBond). It deliberately does NOT consider the deregister flag — a
// deregistered-but-still-bonded operator's verdict still counts at settle, and only a
// fully-withdrawn (bond == 0) operator is dropped. Each distinct operator is read once.
func (s *Server) readBondedSet(ctx context.Context, block *big.Int, verdicts []Verdict, minBond *big.Int) (map[common.Address]bool, error) {
	bonded := make(map[common.Address]bool, len(verdicts))
	for i := range verdicts {
		op := verdicts[i].Operator
		if _, seen := bonded[op]; seen {
			continue
		}
		out, err := s.governor.callAt(ctx, s.ec, block, "bondOf", op)
		if err != nil {
			return nil, err
		}
		bond, ok := out[0].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("quorum_status: bondOf not *big.Int")
		}
		// _bonded: bond != 0 && bond >= minBond.
		bonded[op] = bond.Sign() != 0 && bond.Cmp(minBond) >= 0
	}
	return bonded, nil
}

// observedBlock pins the block this tool's reads are taken at: the current head number.
// Reading it once and threading it through every call gives a consistent snapshot.
func (s *Server) observedBlock(ctx context.Context) (*big.Int, error) {
	bn, err := s.ec.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcp: observed block number: %w", err)
	}
	return new(big.Int).SetUint64(bn), nil
}

// blockTimestamp returns the timestamp of `block` (the same point the reads reflect),
// used to evaluate settle()'s deadline gate against the observed state, not a later head.
func (s *Server) blockTimestamp(ctx context.Context, block *big.Int) (uint64, error) {
	hdr, err := s.ec.HeaderByNumber(ctx, block)
	if err != nil {
		return 0, fmt.Errorf("mcp: observed block header: %w", err)
	}
	return hdr.Time, nil
}

type quorumTally struct {
	votesFor      int // Yes verdicts among BONDED operators (what settle would tally)
	votesAgainst  int // No verdicts among BONDED operators
	bestCount     int
	counted       int // total BONDED verdicts considered
	winningVote   uint8
	winningBucket uint16
	quorumReached bool
}

// tallyQuorum reproduces AIGovernor.settle()'s tally EXACTLY: it considers ONLY
// verdicts whose operator is bonded at the observed block (bonded[op] true), groups
// them by the consensus key (vote, confidenceBucket) — the same _consensusKey settle
// uses — tracks the largest group, and reports quorumReached = (largest group >=
// threshold). A verdict from a withdrawn (unbonded) operator is DROPPED, just as settle
// drops it, so MCP cannot report quorumReached=true for a quorum the chain will settle
// Failed. winningVote/winningBucket name the best group so a non-Yes quorum is legible.
// votesFor / votesAgainst are the Yes / No counts among the BONDED set. Pure projection
// of on-chain reads — it submits nothing.
//
// Structural invariant (load-bearing): AIGovernor sets threshold = n/2 + 1, so AT MOST
// ONE (vote,bucket) group can ever reach quorum — two groups clearing threshold would
// need 2*threshold <= n, i.e. n+2 <= n, impossible. A withdrawal can therefore only
// DESTROY a quorum, never transfer it to a different vote-group. The first-seen strict-`>`
// tie-break below thus only governs the cosmetic winningVote/winningBucket on the
// no-quorum path (settle records Invalid there). If the threshold formula in
// AIGovernor.sol ever drops below n/2+1, this single-winner guarantee breaks and the
// tie-break parity with settle() becomes quorum-affecting — re-audit HIGH-1 then.
func tallyQuorum(verdicts []Verdict, threshold uint8, bonded map[common.Address]bool) quorumTally {
	type key struct {
		vote   uint8
		bucket uint16
	}
	groups := map[key]int{}
	var t quorumTally
	// Iterate in verdict order so ties resolve to the FIRST-seen group, matching
	// settle()'s submitter-order scan (it keeps the earliest key at a given bestCount).
	var bestKey key
	haveBest := false
	for i := range verdicts {
		v := verdicts[i]
		if !bonded[v.Operator] {
			continue
		}
		t.counted++
		k := key{v.Vote, v.ConfidenceBucket}
		groups[k]++
		switch v.Vote {
		case voteYes:
			t.votesFor++
		case voteNo:
			t.votesAgainst++
		}
		if c := groups[k]; c > t.bestCount {
			t.bestCount = c
			bestKey = k
			haveBest = true
		}
	}
	if haveBest {
		t.winningVote = bestKey.vote
		t.winningBucket = bestKey.bucket
	}
	t.quorumReached = t.bestCount >= int(threshold) && threshold > 0
	return t
}

// ----------------------------------------------------------------------------
// 7. operator_reputation
// ----------------------------------------------------------------------------

func (s *Server) toolOperatorReputation(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	op, err := argAddress(args, "operator")
	if err != nil {
		return nil, err
	}
	isOpOut, err := s.governor.call(ctx, s.ec, "isOperator", op)
	if err != nil {
		return nil, err
	}
	isOp, ok := isOpOut[0].(bool)
	if !ok {
		return nil, fmt.Errorf("operator_reputation: isOperator not bool")
	}
	bondOut, err := s.governor.call(ctx, s.ec, "bondOf", op)
	if err != nil {
		return nil, err
	}
	bond, ok := bondOut[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("operator_reputation: bondOf not *big.Int")
	}
	weightOut, err := s.rep.call(ctx, s.ec, "weightOf", op)
	if err != nil {
		return nil, err
	}
	weight, ok := weightOut[0].(uint32)
	if !ok {
		return nil, fmt.Errorf("operator_reputation: weightOf not uint32")
	}
	rateOut, err := s.rep.call(ctx, s.ec, "agreementRateBps", op)
	if err != nil {
		return nil, err
	}
	rate, ok := rateOut[0].(uint32)
	if !ok {
		return nil, fmt.Errorf("operator_reputation: agreementRateBps not uint32")
	}
	rep, err := callStruct[Rep](ctx, s.rep, s.ec, "repOf", op)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"isOperator":       isOp,
		"bond":             bond.String(),
		"weight":           weight,
		"agreementRateBps": rate,
		"rep":              repJSON(&rep),
	}, nil
}

// ----------------------------------------------------------------------------
// 8. pending_operations
// ----------------------------------------------------------------------------

func (s *Server) toolPendingOperations(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := argLimit(args, defaultLimit)
	// Pin reads to one block so taskCount, each thought, and the "now" used for the
	// deadlinePassed flag all reflect the same chain point.
	block, err := s.observedBlock(ctx)
	if err != nil {
		return nil, err
	}
	now, err := s.blockTimestamp(ctx, block)
	if err != nil {
		return nil, err
	}
	count, err := s.readTaskCountAt(ctx, block)
	if err != nil {
		return nil, err
	}
	open, truncated, scannedFrom, err := s.readPendingOperations(ctx, block, count, limit, now)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"taskCount": count.String(),
		"pending":   open,
		// truncated is true when OLDER tasks below the scanned window were NOT inspected,
		// so the caller knows this list may be incomplete (a deep still-Open task can
		// hide below the tail window). scannedFrom..(taskCount-1) is the range looked at.
		"truncated":     truncated,
		"scannedFrom":   scannedFrom.String(),
		"observedBlock": block.String(),
	}, nil
}

// readPendingOperations scans the tail of taskCount descending and returns thoughts
// still in Open status, capped at limit. (Open means the task is accepting verdicts or
// awaiting settle; the chain only leaves Open via settle.) Each entry is annotated with
// deadlinePassed = now >= deadline, so the caller sees that a still-"Open" task whose
// voting window has CLOSED is settle-ready even though settle was never called. Returns
// truncated=true when the scan stopped above task 0 (older tasks were not inspected),
// and the lowest task id scanned. The bounded window plus the per-request eth_call
// ceiling keep a huge taskCount from issuing an unbounded scan.
func (s *Server) readPendingOperations(ctx context.Context, block, count *big.Int, limit int, now uint64) ([]interface{}, bool, *big.Int, error) {
	out := []interface{}{}
	last := new(big.Int).Sub(count, big.NewInt(1))
	if count.Sign() == 0 {
		return out, false, big.NewInt(0), nil
	}
	scanWindow := int64(limit)
	if scanWindow < pendingScanFloor {
		scanWindow = pendingScanFloor
	}
	floor := new(big.Int).Sub(last, big.NewInt(scanWindow-1))
	if floor.Sign() < 0 {
		floor = big.NewInt(0)
	}
	// lowestInspected tracks the smallest task id we actually read; truncated is then
	// simply "did we stop before reaching task 0". This is honest whether the loop ended
	// on the limit or on the window floor.
	lowestInspected := new(big.Int).Set(last)
	for i := new(big.Int).Set(last); i.Cmp(floor) >= 0 && len(out) < limit; i.Sub(i, big.NewInt(1)) {
		lowestInspected.Set(i)
		t, err := s.readThoughtAt(ctx, block, i)
		if err != nil {
			return nil, false, nil, err
		}
		if t.Status != statusOpen {
			continue
		}
		res := thoughtJSON(t)
		res["taskId"] = new(big.Int).Set(i).String()
		res["status"] = derivedStatus(t.Status)
		// A still-Open task past its deadline is settle-ready but un-settled — flag it so
		// the LLM does not read "Open" as "still accepting / outcome not yet fixed".
		res["deadlinePassed"] = now >= t.Deadline
		out = append(out, res)
	}
	truncated := lowestInspected.Sign() > 0
	return out, truncated, lowestInspected, nil
}

func (s *Server) readTaskCountAt(ctx context.Context, block *big.Int) (*big.Int, error) {
	out, err := s.governor.callAt(ctx, s.ec, block, "taskCount")
	if err != nil {
		return nil, err
	}
	c, ok := out[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("pending_operations: taskCount not *big.Int")
	}
	return c, nil
}

// ----------------------------------------------------------------------------
// JSON projections — stable, all-scalar renderings of the mirror structs.
// ----------------------------------------------------------------------------

func roundJSON(r *Round) map[string]interface{} {
	return map[string]interface{}{
		"modelSpecHash":   hexBytes32(r.ModelSpecHash),
		"promptHash":      hexBytes32(r.PromptHash),
		"knobKey":         r.KnobKey,
		"lo":              bigString(r.Lo),
		"hi":              bigString(r.Hi),
		"n":               r.N,
		"threshold":       r.Threshold,
		"openedAt":        r.OpenedAt,
		"deadline":        r.Deadline,
		"opener":          r.Opener.Hex(),
		"status":          r.Status,
		"statusLabel":     derivedStatus(r.Status),
		"submissionCount": r.SubmissionCount,
		"canonicalValue":  bigString(r.CanonicalValue),
	}
}

func proposalsJSON(ps []Proposal) []interface{} {
	out := make([]interface{}, 0, len(ps))
	for i := range ps {
		out = append(out, map[string]interface{}{
			"operator":         ps[i].Operator.Hex(),
			"value":            bigString(ps[i].Value),
			"confidenceBucket": ps[i].ConfidenceBucket,
			"evidenceHash":     hexBytes32(ps[i].EvidenceHash),
			"submittedAt":      ps[i].SubmittedAt,
		})
	}
	return out
}

func thoughtJSON(t *Thought) map[string]interface{} {
	return map[string]interface{}{
		"modelSpecHash":   hexBytes32(t.ModelSpecHash),
		"promptHash":      hexBytes32(t.PromptHash),
		"evidenceHash":    hexBytes32(t.EvidenceHash),
		"n":               t.N,
		"threshold":       t.Threshold,
		"openedAt":        t.OpenedAt,
		"deadline":        t.Deadline,
		"opener":          t.Opener.Hex(),
		"rawStatus":       t.Status,
		"submissionCount": t.SubmissionCount,
		"knobKey":         t.KnobKey,
		"canonicalVote":   t.CanonicalVote,
		"canonicalBucket": t.CanonicalBucket,
		"agreeCount":      t.AgreeCount,
		"evidenceRoot":    hexBytes32(t.EvidenceRoot),
		"commitReveal":    t.CommitReveal,
		"commitDeadline":  t.CommitDeadline,
		"revealDeadline":  t.RevealDeadline,
	}
}

func verdictsJSON(vs []Verdict) []interface{} {
	out := make([]interface{}, 0, len(vs))
	for i := range vs {
		out = append(out, map[string]interface{}{
			"operator":         vs[i].Operator.Hex(),
			"vote":             vs[i].Vote,
			"confidenceBucket": vs[i].ConfidenceBucket,
			"evidenceHash":     hexBytes32(vs[i].EvidenceHash),
			"submittedAt":      vs[i].SubmittedAt,
		})
	}
	return out
}

func receiptJSON(rc *ThoughtReceipt) map[string]interface{} {
	return map[string]interface{}{
		"modelId":      hexBytes32(rc.ModelId),
		"promptHash":   hexBytes32(rc.PromptHash),
		"outputHash":   hexBytes32(rc.OutputHash),
		"paymentHash":  hexBytes32(rc.PaymentHash),
		"quorumProof":  hexBytes32(rc.QuorumProof),
		"payer":        rc.Payer.Hex(),
		"operator":     rc.Operator.Hex(),
		"cost":         bigString(rc.Cost),
		"registeredAt": rc.RegisteredAt,
		"blockNumber":  rc.BlockNumber,
	}
}

func repJSON(r *Rep) map[string]interface{} {
	return map[string]interface{}{
		"weightBps":    r.WeightBps,
		"participated": r.Participated,
		"agreed":       r.Agreed,
		"lastTaskId1":  r.LastTaskId1,
		"lastUpdated":  r.LastUpdated,
	}
}

func hexBytes32(b [32]byte) string {
	return common.BytesToHash(b[:]).Hex()
}
