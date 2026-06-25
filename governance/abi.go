// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"math/big"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/mcp/evmread"
)

// This file holds the minimal, hand-written ABI for the four governance contracts.
// Only the VIEW functions and the structs the eight read tools touch are declared —
// the package never packs a state-mutating method, so it has no calldata path that
// could change chain state. The struct tuple component order/types below mirror the
// Solidity sources EXACTLY (AIParams.sol, AIGovernor.sol, IAIGovernor.sol,
// AIThoughtRegistry.sol, AIReputation.sol); the parity tests assert that.
//
// The chain-read mechanics (Caller, Contract.Call, CallStruct, the per-request call
// ceiling) live in github.com/luxfi/mcp/evmread — the SOLE geth-importing adapter.
// This package contributes only the domain ABIs and structs and composes them over
// evmread; it never imports geth's transactor/signing surface.

// ----------------------------------------------------------------------------
// Solidity-mirror structs. Field ORDER and Go types match the .sol tuple layout
// exactly so abi.UnpackIntoInterface decodes a returned struct field-for-field.
// (common.Address and *big.Int are read-only value types — not write-capable.)
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

// readParamsContract / etc. bind the ABI strings to addresses via evmread. Kept as a
// tiny constructor set so newServer reads exactly like before but through the adapter.
func bindContracts(cfg Config) (params, governor, registry, rep *evmread.Contract, err error) {
	if params, err = evmread.NewContract(aiParamsABI, cfg.AIParams); err != nil {
		return
	}
	if governor, err = evmread.NewContract(aiGovernorABI, cfg.AIGovernor); err != nil {
		return
	}
	if registry, err = evmread.NewContract(aiThoughtRegistryABI, cfg.AIThoughtRegistry); err != nil {
		return
	}
	rep, err = evmread.NewContract(aiReputationABI, cfg.AIReputation)
	return
}
