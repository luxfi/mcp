// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"

	"github.com/luxfi/mcp/evmread"
)

// ChainObservation is the verifiable record of WHAT the chain said and WHEN.
//
// An operator-LLM reads chain facts through the MCP read tools while deliberating,
// then signs a verdict it submits through the normal AIGovernor tx path (NOT through
// this server). To make that verdict checkable against the state it claims to have
// seen, the operator binds an observation hash into the verdict's evidence. The
// observation pins the block context (number + hash + chainId + timestamp) and the
// exact reads a tool returned, so a third party can (a) re-derive the hash from the
// same reads and (b) detect when the observation is stale or sits on a reorged block.
//
// It is DETERMINISTICALLY SERIALIZABLE — Canonical() emits stable JSON with sorted
// keys (Go's encoding/json sorts map keys, and we sort the Reads slice by key) — and
// HASHABLE via keccak256 over those canonical bytes (Hash). Two parties that observed
// the identical facts at the identical block produce byte-identical Canonical() and
// thus the identical Hash.
type ChainObservation struct {
	// Block context: the point in the chain the reads were taken at.
	ChainID     *big.Int    `json:"chainId"`
	BlockNumber uint64      `json:"blockNumber"`
	BlockHash   common.Hash `json:"blockHash"`
	Timestamp   uint64      `json:"timestamp"`

	// Tool is the read tool that produced this observation (e.g. "param_value").
	Tool string `json:"tool"`

	// Reads is the set of named facts the tool returned, each an already-canonical
	// value. Kept as sorted key/value pairs (not a Go map) so the serialization is
	// deterministic regardless of insertion order.
	Reads []ObservedFact `json:"reads"`
}

// ObservedFact is one named, canonically-encoded chain fact inside an observation.
// Value is a JSON-canonical encoding of the fact (decimal string for integers, hex
// for bytes, etc.) so the hash is stable and language-independent.
type ObservedFact struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// NewObservation builds an observation by reading the current chain head once and
// stamping it with the supplied reads (which the caller has already canonicalized).
// The reads are sorted by key so the observation is order-independent. A domain tool
// (e.g. governance) calls this with the exact facts it returned, so its result can be
// bound into a verdict and re-verified later.
func NewObservation(ctx context.Context, ec evmread.Caller, tool string, reads []ObservedFact) (*ChainObservation, error) {
	chainID, err := ec.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcp: observation chainID: %w", err)
	}
	head, err := ec.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp: observation head: %w", err)
	}
	o := &ChainObservation{
		ChainID:     chainID,
		BlockNumber: head.Number.Uint64(),
		BlockHash:   head.Hash(),
		Timestamp:   head.Time,
		Tool:        tool,
		Reads:       append([]ObservedFact(nil), reads...),
	}
	o.sortReads()
	return o, nil
}

// sortReads orders Reads by Key (stable insertion-sort; read sets are tiny) and then
// collapses duplicate keys to LAST-writer-wins, so Canonical() is independent of the
// order the tool appended facts AND a set that names the same key twice cannot yield two
// different hashes (which would let two parties "observe" different values under one
// key). The sort is stable, so among equal keys the last-APPENDED value is kept.
func (o *ChainObservation) sortReads() {
	for i := 1; i < len(o.Reads); i++ {
		k := o.Reads[i]
		j := i
		for j > 0 && o.Reads[j-1].Key > k.Key {
			o.Reads[j] = o.Reads[j-1]
			j--
		}
		o.Reads[j] = k
	}
	o.Reads = dedupLastWins(o.Reads)
}

// dedupLastWins removes earlier entries that share a Key with a later entry, on an
// already key-sorted (and stable) slice: for a run of equal keys it keeps the last one.
func dedupLastWins(reads []ObservedFact) []ObservedFact {
	if len(reads) < 2 {
		return reads
	}
	out := reads[:0]
	for i := 0; i < len(reads); i++ {
		// Skip this entry if the NEXT entry has the same key (a later writer wins).
		if i+1 < len(reads) && reads[i+1].Key == reads[i].Key {
			continue
		}
		out = append(out, reads[i])
	}
	return out
}

// Canonical returns the deterministic byte serialization of the observation: the
// ChainID is rendered as a decimal string and the block hash as 0x-hex (both via the
// MarshalJSON below), the Reads are sorted, and Go's encoder writes struct fields in
// declaration order. The result is stable across processes and languages.
func (o *ChainObservation) Canonical() []byte {
	// Defensive copy + sort so Canonical() never depends on external mutation order.
	c := &ChainObservation{
		ChainID:     o.ChainID,
		BlockNumber: o.BlockNumber,
		BlockHash:   o.BlockHash,
		Timestamp:   o.Timestamp,
		Tool:        o.Tool,
		Reads:       append([]ObservedFact(nil), o.Reads...),
	}
	c.sortReads()
	b, err := json.Marshal(canonicalView{
		ChainID:     bigString(c.ChainID),
		BlockNumber: c.BlockNumber,
		BlockHash:   c.BlockHash.Hex(),
		Timestamp:   c.Timestamp,
		Tool:        c.Tool,
		Reads:       c.Reads,
	})
	if err != nil {
		// canonicalView is composed only of marshalable scalars/strings/slices, so
		// json.Marshal cannot fail here; return an empty slice rather than panic in
		// library code if it somehow does.
		return []byte{}
	}
	return b
}

// canonicalView is the fixed-shape, all-scalar projection that Canonical() hashes.
// Using explicit string forms (decimal chainId, 0x-hex hash) removes any ambiguity
// from big.Int / common.Hash JSON encodings across implementations.
type canonicalView struct {
	ChainID     string         `json:"chainId"`
	BlockNumber uint64         `json:"blockNumber"`
	BlockHash   string         `json:"blockHash"`
	Timestamp   uint64         `json:"timestamp"`
	Tool        string         `json:"tool"`
	Reads       []ObservedFact `json:"reads"`
}

// Hash is keccak256 over the canonical bytes — the value an operator binds into its
// verdict so the verdict can later be checked against the observed chain state.
func (o *ChainObservation) Hash() common.Hash {
	return common.BytesToHash(crypto.Keccak256(o.Canonical()))
}

// Verify checks the observation is still current: the chain must not have advanced
// more than maxAgeBlocks past the observed block, and the canonical block at the
// observed height must still hash to the observed hash (a reorg changes it). It
// returns (fresh, error): fresh is false (with a descriptive error) when the
// observation is stale or sits on a block no longer canonical, true when it is still
// safe to act on. A read error is surfaced as a non-nil error with fresh=false.
//
// maxAgeBlocks == 0 means "must be the exact head block" (zero tolerance).
func (o *ChainObservation) Verify(ctx context.Context, ec evmread.Caller, maxAgeBlocks uint64) (bool, error) {
	// Chain identity: the observation must be checked against the SAME chain it was taken
	// on. A mismatch means we are pointed at a different network entirely (e.g. testnet vs
	// mainnet), so block numbers/hashes are not comparable and the observation is invalid
	// here. This is a cheap call and guards against silently verifying on the wrong chain.
	chainID, err := ec.ChainID(ctx)
	if err != nil {
		return false, fmt.Errorf("mcp: verify chainID: %w", err)
	}
	if o.ChainID == nil || chainID.Cmp(o.ChainID) != 0 {
		return false, fmt.Errorf("mcp: chain mismatch: observation chainId=%s, live chainId=%s", bigString(o.ChainID), chainID.String())
	}
	head, err := ec.BlockNumber(ctx)
	if err != nil {
		return false, fmt.Errorf("mcp: verify head number: %w", err)
	}
	if head < o.BlockNumber {
		// The chain we are checking against is BEHIND the observation — either a
		// reorg shortened it or we are pointed at a different (lagging) node. Either
		// way the observation cannot be trusted as current.
		return false, fmt.Errorf("mcp: observation is ahead of chain head (obs=%d head=%d): reorg or wrong node", o.BlockNumber, head)
	}
	if age := head - o.BlockNumber; age > maxAgeBlocks {
		return false, fmt.Errorf("mcp: stale observation: chain advanced %d blocks past observed %d (max %d)", age, o.BlockNumber, maxAgeBlocks)
	}
	// Reorg / fork check: the block at the observed height must still hash to what we
	// recorded. If the observed block was reorged out, this hash differs.
	hdr, err := ec.HeaderByNumber(ctx, new(big.Int).SetUint64(o.BlockNumber))
	if err != nil {
		return false, fmt.Errorf("mcp: verify header @ %d: %w", o.BlockNumber, err)
	}
	if hdr.Hash() != o.BlockHash {
		return false, fmt.Errorf("mcp: reorg detected at block %d: observed %s, canonical %s", o.BlockNumber, o.BlockHash.Hex(), hdr.Hash().Hex())
	}
	return true, nil
}

// bigString renders a *big.Int as a decimal string, treating nil as "0".
func bigString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}
