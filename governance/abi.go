// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/luxfi/geth/accounts/abi"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"

	gethereum "github.com/luxfi/geth"
)

// This file holds the minimal, hand-written ABI for the four governance contracts
// and a single read-only call helper. Only the VIEW functions and the structs the
// eight read tools touch are declared — the package never packs a state-mutating
// method, so it has no calldata path that could change chain state. The struct
// tuple component order/types below mirror the Solidity sources EXACTLY
// (AIParams.sol, AIGovernor.sol, IAIGovernor.sol, AIThoughtRegistry.sol,
// AIReputation.sol); the parity tests assert that.

// EthCaller is the minimal, READ-ONLY chain surface this server needs. Both the
// production *ethclient.Client (dialed in New) and the in-process simulated test
// backend's Client satisfy it. It deliberately exposes NO transaction-sending
// method: there is no Send/SendTransaction here, so no caller of this package can
// submit a tx through it. (Decomplecting, Hickey: the dependency is "a thing that
// can read the chain", not "a URL" — which is also what makes the tests injectable.)
type EthCaller interface {
	CallContract(ctx context.Context, call gethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	ChainID(ctx context.Context) (*big.Int, error)
	BlockNumber(ctx context.Context) (uint64, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// ----------------------------------------------------------------------------
// Solidity-mirror structs. Field ORDER and Go types match the .sol tuple layout
// exactly so abi.UnpackIntoInterface decodes a returned struct field-for-field.
// ----------------------------------------------------------------------------

// Round mirrors AIParams.Round (AIParams.sol struct order).
type Round struct {
	ModelSpecHash   [32]byte
	PromptHash      [32]byte
	KnobKey         string
	Lo              *big.Int
	Hi              *big.Int
	N               uint8
	Threshold       uint8
	OpenedAt        uint64
	Deadline        uint64
	Opener          common.Address
	Status          uint8
	SubmissionCount uint8
	CanonicalValue  *big.Int
}

// Proposal mirrors AIParams.Proposal.
type Proposal struct {
	Operator         common.Address
	Value            *big.Int
	ConfidenceBucket uint16
	EvidenceHash     [32]byte
	SubmittedAt      uint64
}

// Thought mirrors IAIGovernor.Thought (field order is load-bearing — settle fills
// the tail fields, and the commit-reveal trio closes the struct).
type Thought struct {
	ModelSpecHash   [32]byte
	PromptHash      [32]byte
	EvidenceHash    [32]byte
	N               uint8
	Threshold       uint8
	OpenedAt        uint64
	Deadline        uint64
	Opener          common.Address
	Status          uint8
	SubmissionCount uint8
	KnobKey         string
	CanonicalVote   uint8
	CanonicalBucket uint16
	AgreeCount      uint8
	EvidenceRoot    [32]byte
	CommitReveal    bool
	CommitDeadline  uint64
	RevealDeadline  uint64
}

// Verdict mirrors IAIGovernor.Verdict.
type Verdict struct {
	Operator         common.Address
	Vote             uint8
	ConfidenceBucket uint16
	EvidenceHash     [32]byte
	SubmittedAt      uint64
}

// ThoughtReceipt mirrors IAIThoughtRegistry.ThoughtReceipt.
type ThoughtReceipt struct {
	ModelId      [32]byte
	PromptHash   [32]byte
	OutputHash   [32]byte
	PaymentHash  [32]byte
	QuorumProof  [32]byte
	Payer        common.Address
	Operator     common.Address
	Cost         *big.Int // uint96
	RegisteredAt uint64
	BlockNumber  uint64
}

// Rep mirrors AIReputation.Rep.
type Rep struct {
	WeightBps    uint32
	Participated uint32
	Agreed       uint32
	LastTaskId1  uint64
	LastUpdated  uint64
}

// ----------------------------------------------------------------------------
// ABI JSON — view functions only. Tuple components carry names so the unpacker
// can map them, but we decode into the mirror structs above by position.
// ----------------------------------------------------------------------------

const roundTuple = `{"name":"r","type":"tuple","components":[` +
	`{"name":"modelSpecHash","type":"bytes32"},` +
	`{"name":"promptHash","type":"bytes32"},` +
	`{"name":"knobKey","type":"string"},` +
	`{"name":"lo","type":"uint256"},` +
	`{"name":"hi","type":"uint256"},` +
	`{"name":"n","type":"uint8"},` +
	`{"name":"threshold","type":"uint8"},` +
	`{"name":"openedAt","type":"uint64"},` +
	`{"name":"deadline","type":"uint64"},` +
	`{"name":"opener","type":"address"},` +
	`{"name":"status","type":"uint8"},` +
	`{"name":"submissionCount","type":"uint8"},` +
	`{"name":"canonicalValue","type":"uint256"}]}`

const proposalTuple = `{"name":"p","type":"tuple","components":[` +
	`{"name":"operator","type":"address"},` +
	`{"name":"value","type":"uint256"},` +
	`{"name":"confidenceBucket","type":"uint16"},` +
	`{"name":"evidenceHash","type":"bytes32"},` +
	`{"name":"submittedAt","type":"uint64"}]}`

const thoughtTuple = `{"name":"t","type":"tuple","components":[` +
	`{"name":"modelSpecHash","type":"bytes32"},` +
	`{"name":"promptHash","type":"bytes32"},` +
	`{"name":"evidenceHash","type":"bytes32"},` +
	`{"name":"n","type":"uint8"},` +
	`{"name":"threshold","type":"uint8"},` +
	`{"name":"openedAt","type":"uint64"},` +
	`{"name":"deadline","type":"uint64"},` +
	`{"name":"opener","type":"address"},` +
	`{"name":"status","type":"uint8"},` +
	`{"name":"submissionCount","type":"uint8"},` +
	`{"name":"knobKey","type":"string"},` +
	`{"name":"canonicalVote","type":"uint8"},` +
	`{"name":"canonicalBucket","type":"uint16"},` +
	`{"name":"agreeCount","type":"uint8"},` +
	`{"name":"evidenceRoot","type":"bytes32"},` +
	`{"name":"commitReveal","type":"bool"},` +
	`{"name":"commitDeadline","type":"uint64"},` +
	`{"name":"revealDeadline","type":"uint64"}]}`

const verdictTuple = `{"name":"v","type":"tuple","components":[` +
	`{"name":"operator","type":"address"},` +
	`{"name":"vote","type":"uint8"},` +
	`{"name":"confidenceBucket","type":"uint16"},` +
	`{"name":"evidenceHash","type":"bytes32"},` +
	`{"name":"submittedAt","type":"uint64"}]}`

const receiptTuple = `{"name":"rc","type":"tuple","components":[` +
	`{"name":"modelId","type":"bytes32"},` +
	`{"name":"promptHash","type":"bytes32"},` +
	`{"name":"outputHash","type":"bytes32"},` +
	`{"name":"paymentHash","type":"bytes32"},` +
	`{"name":"quorumProof","type":"bytes32"},` +
	`{"name":"payer","type":"address"},` +
	`{"name":"operator","type":"address"},` +
	`{"name":"cost","type":"uint96"},` +
	`{"name":"registeredAt","type":"uint64"},` +
	`{"name":"blockNumber","type":"uint64"}]}`

const repTuple = `{"name":"rep","type":"tuple","components":[` +
	`{"name":"weightBps","type":"uint32"},` +
	`{"name":"participated","type":"uint32"},` +
	`{"name":"agreed","type":"uint32"},` +
	`{"name":"lastTaskId1","type":"uint64"},` +
	`{"name":"lastUpdated","type":"uint64"}]}`

// aiParamsABI: AIParams view functions used by param_value / param_history.
const aiParamsABI = `[` +
	`{"type":"function","stateMutability":"view","name":"valueOf","inputs":[{"name":"modelSpecHash","type":"bytes32"},{"name":"knobKey","type":"string"}],"outputs":[{"name":"value","type":"uint256"},{"name":"decided","type":"bool"}]},` +
	`{"type":"function","stateMutability":"view","name":"roundCount","inputs":[],"outputs":[{"name":"","type":"uint256"}]},` +
	`{"type":"function","stateMutability":"view","name":"getRound","inputs":[{"name":"roundId","type":"uint256"}],"outputs":[` + roundTuple + `]},` +
	`{"type":"function","stateMutability":"view","name":"getProposals","inputs":[{"name":"roundId","type":"uint256"}],"outputs":[{"name":"","type":"tuple[]","components":[` +
	`{"name":"operator","type":"address"},{"name":"value","type":"uint256"},{"name":"confidenceBucket","type":"uint16"},{"name":"evidenceHash","type":"bytes32"},{"name":"submittedAt","type":"uint64"}]}]}` +
	`]`

// aiGovernorABI: AIGovernor view functions used by thought_status / quorum_status /
// operator_reputation / pending_operations.
const aiGovernorABI = `[` +
	`{"type":"function","stateMutability":"view","name":"getThought","inputs":[{"name":"taskId","type":"uint256"}],"outputs":[` + thoughtTuple + `]},` +
	`{"type":"function","stateMutability":"view","name":"getVerdicts","inputs":[{"name":"taskId","type":"uint256"}],"outputs":[{"name":"","type":"tuple[]","components":[` +
	`{"name":"operator","type":"address"},{"name":"vote","type":"uint8"},{"name":"confidenceBucket","type":"uint16"},{"name":"evidenceHash","type":"bytes32"},{"name":"submittedAt","type":"uint64"}]}]},` +
	`{"type":"function","stateMutability":"view","name":"taskCount","inputs":[],"outputs":[{"name":"","type":"uint256"}]},` +
	`{"type":"function","stateMutability":"view","name":"isOperator","inputs":[{"name":"who","type":"address"}],"outputs":[{"name":"","type":"bool"}]},` +
	`{"type":"function","stateMutability":"view","name":"bondOf","inputs":[{"name":"who","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},` +
	`{"type":"function","stateMutability":"view","name":"minBond","inputs":[],"outputs":[{"name":"","type":"uint256"}]}` +
	`]`

// aiThoughtRegistryABI: registry view functions used by receipt_lookup.
const aiThoughtRegistryABI = `[` +
	`{"type":"function","stateMutability":"view","name":"exists","inputs":[{"name":"receiptId","type":"bytes32"}],"outputs":[{"name":"","type":"bool"}]},` +
	`{"type":"function","stateMutability":"view","name":"getReceipt","inputs":[{"name":"receiptId","type":"bytes32"}],"outputs":[` + receiptTuple + `]},` +
	`{"type":"function","stateMutability":"view","name":"receiptCount","inputs":[],"outputs":[{"name":"","type":"uint256"}]}` +
	`]`

// aiReputationABI: reputation view functions used by operator_reputation.
const aiReputationABI = `[` +
	`{"type":"function","stateMutability":"view","name":"weightOf","inputs":[{"name":"operator","type":"address"}],"outputs":[{"name":"","type":"uint32"}]},` +
	`{"type":"function","stateMutability":"view","name":"repOf","inputs":[{"name":"operator","type":"address"}],"outputs":[` + repTuple + `]},` +
	`{"type":"function","stateMutability":"view","name":"agreementRateBps","inputs":[{"name":"operator","type":"address"}],"outputs":[{"name":"","type":"uint32"}]}` +
	`]`

// boundABI pairs a parsed ABI with the address it is deployed at. A read tool
// packs a method's calldata, sends it via EthCaller.CallContract (eth_call), and
// unpacks the return. There is exactly one chain-access verb here (CallContract),
// which is the read-only eth_call — no path packs or sends a transaction.
type boundABI struct {
	abi  abi.ABI
	addr common.Address
}

func newBoundABI(jsonABI string, addr common.Address) (*boundABI, error) {
	parsed, err := abi.JSON(strings.NewReader(jsonABI))
	if err != nil {
		return nil, fmt.Errorf("mcp: parse ABI: %w", err)
	}
	return &boundABI{abi: parsed, addr: addr}, nil
}

// call packs `method`(args...), executes it as a read-only eth_call against the
// bound address at the latest block, and returns the decoded output values.
func (b *boundABI) call(ctx context.Context, ec EthCaller, method string, args ...interface{}) ([]interface{}, error) {
	return b.callAt(ctx, ec, nil, method, args...)
}

// callAt is `call` pinned to a specific block (nil = latest). Pinning lets a tool
// that issues SEVERAL reads which must agree (e.g. quorum_status reading verdicts and
// then each operator's bond) take them all at ONE block, so a state change between the
// reads — a bond withdraw racing the tally — cannot produce an inconsistent snapshot.
// The in-process test backend ignores the block arg (it has only latest state); the
// production *ethclient.Client honors it.
func (b *boundABI) callAt(ctx context.Context, ec EthCaller, block *big.Int, method string, args ...interface{}) ([]interface{}, error) {
	m, ok := b.abi.Methods[method]
	if !ok {
		return nil, fmt.Errorf("mcp: unknown method %q", method)
	}
	in, err := b.abi.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("mcp: pack %s: %w", method, err)
	}
	out, err := ec.CallContract(ctx, gethereum.CallMsg{To: &b.addr, Data: in}, block)
	if err != nil {
		return nil, fmt.Errorf("mcp: eth_call %s @ %s: %w", method, b.addr.Hex(), err)
	}
	vals, err := m.Outputs.Unpack(out)
	if err != nil {
		return nil, fmt.Errorf("mcp: unpack %s: %w", method, err)
	}
	return vals, nil
}

// callStruct packs `method`(args...), runs the read-only eth_call, and unpacks a
// SINGLE struct (or slice-of-struct) return into a value of type T, mapping the
// Solidity tuple field-for-field by position.
//
// geth's abi.UnpackIntoInterface special-cases a single output: it treats the
// destination as a wrapper struct and writes the unpacked value into its FIRST field
// (Arguments.copyAtomic). So we hand it a one-field wrapper whose field is T; geth
// then field-copies the tuple into it by index — which is exactly why T's field order
// MUST mirror the Solidity struct (it does; the parity tests assert it).
func callStruct[T any](ctx context.Context, b *boundABI, ec EthCaller, method string, args ...interface{}) (T, error) {
	return callStructAt[T](ctx, b, ec, nil, method, args...)
}

// callStructAt is `callStruct` pinned to a specific block (nil = latest); see callAt
// for why pinning matters. quorum_status uses it to read getThought / getVerdicts at
// the same block it reads the bonds, for a consistent settle-equivalent snapshot.
func callStructAt[T any](ctx context.Context, b *boundABI, ec EthCaller, block *big.Int, method string, args ...interface{}) (T, error) {
	var wrap struct{ V T }
	in, err := b.abi.Pack(method, args...)
	if err != nil {
		return wrap.V, fmt.Errorf("mcp: pack %s: %w", method, err)
	}
	out, err := ec.CallContract(ctx, gethereum.CallMsg{To: &b.addr, Data: in}, block)
	if err != nil {
		return wrap.V, fmt.Errorf("mcp: eth_call %s @ %s: %w", method, b.addr.Hex(), err)
	}
	if err := b.abi.UnpackIntoInterface(&wrap, method, out); err != nil {
		return wrap.V, fmt.Errorf("mcp: unpack %s: %w", method, err)
	}
	return wrap.V, nil
}
