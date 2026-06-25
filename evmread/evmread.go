// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package evmread is the SOLE EVM read adapter for the governance MCP stack: it is
// the one and only package that imports go-ethereum (luxfi/geth). It exposes a
// minimal, READ-ONLY chain surface (Caller) and the calldata pack/eth_call/unpack
// helpers a domain uses to read view functions — and nothing that can sign or submit
// a transaction.
//
// Decomplecting (Rich Hickey): the dependency a read tool actually has is "a thing
// that can read the chain", not "a URL" and not "go-ethereum". This package names
// exactly that thing (Caller) and the read verbs over it (Contract.Call,
// CallStruct), so a domain package (governance) can compose chain reads WITHOUT
// importing geth at all. The read-only guarantee is anchored here: Caller carries no
// Send/SignTx/Transactor method, so no consumer of this package has a calldata path
// that could change chain state.
package evmread

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/luxfi/geth/accounts/abi"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"

	gethereum "github.com/luxfi/geth"
)

// Caller is the minimal, READ-ONLY chain surface the governance reads need. Both the
// production *ethclient.Client and an in-process simulated/test backend's Client
// satisfy it. It deliberately exposes NO transaction-sending method: there is no
// Send/SendTransaction here, so no caller of this package can submit a tx through it.
// (The read-only gate in luxfi/mcp asserts this method set is EXACTLY these four.)
type Caller interface {
	CallContract(ctx context.Context, call gethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
	ChainID(ctx context.Context) (*big.Int, error)
	BlockNumber(ctx context.Context) (uint64, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// Contract pairs a parsed ABI with the address it is deployed at. A read tool packs a
// method's calldata, sends it via Caller.CallContract (eth_call), and unpacks the
// return. There is exactly one chain-access verb here (CallContract), which is the
// read-only eth_call — no path packs or sends a transaction.
type Contract struct {
	abi  abi.ABI
	addr common.Address
}

// NewContract parses the JSON ABI and binds it to addr. The ABI should declare only
// the VIEW functions the reads touch; this package never packs a state-mutating
// method, so there is no calldata path that could change chain state.
func NewContract(jsonABI string, addr common.Address) (*Contract, error) {
	parsed, err := abi.JSON(strings.NewReader(jsonABI))
	if err != nil {
		return nil, fmt.Errorf("evmread: parse ABI: %w", err)
	}
	return &Contract{abi: parsed, addr: addr}, nil
}

// Call packs `method`(args...), executes it as a read-only eth_call against the bound
// address at the latest block, and returns the decoded output values.
func (c *Contract) Call(ctx context.Context, ec Caller, method string, args ...interface{}) ([]interface{}, error) {
	return c.CallAt(ctx, ec, nil, method, args...)
}

// CallAt is Call pinned to a specific block (nil = latest). Pinning lets a tool that
// issues SEVERAL reads which must agree (e.g. a quorum tally reading verdicts and then
// each operator's bond) take them all at ONE block, so a state change between the reads
// — a bond withdraw racing the tally — cannot produce an inconsistent snapshot. An
// in-process test backend may ignore the block arg (it has only latest state); the
// production *ethclient.Client honors it.
func (c *Contract) CallAt(ctx context.Context, ec Caller, block *big.Int, method string, args ...interface{}) ([]interface{}, error) {
	m, ok := c.abi.Methods[method]
	if !ok {
		return nil, fmt.Errorf("evmread: unknown method %q", method)
	}
	in, err := c.abi.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("evmread: pack %s: %w", method, err)
	}
	out, err := ec.CallContract(ctx, gethereum.CallMsg{To: &c.addr, Data: in}, block)
	if err != nil {
		return nil, fmt.Errorf("evmread: eth_call %s @ %s: %w", method, c.addr.Hex(), err)
	}
	vals, err := m.Outputs.Unpack(out)
	if err != nil {
		return nil, fmt.Errorf("evmread: unpack %s: %w", method, err)
	}
	return vals, nil
}

// CallStruct packs `method`(args...), runs the read-only eth_call, and unpacks a SINGLE
// struct (or slice-of-struct) return into a value of type T, mapping the Solidity tuple
// field-for-field by position.
//
// geth's abi.UnpackIntoInterface special-cases a single output: it treats the
// destination as a wrapper struct and writes the unpacked value into its FIRST field
// (Arguments.copyAtomic). So we hand it a one-field wrapper whose field is T; geth then
// field-copies the tuple into it by index — which is exactly why T's field order MUST
// mirror the Solidity struct.
func CallStruct[T any](ctx context.Context, c *Contract, ec Caller, method string, args ...interface{}) (T, error) {
	return CallStructAt[T](ctx, c, ec, nil, method, args...)
}

// CallStructAt is CallStruct pinned to a specific block (nil = latest); see CallAt for
// why pinning matters. A quorum tally uses it to read getThought / getVerdicts at the
// same block it reads the bonds, for a consistent settle-equivalent snapshot.
func CallStructAt[T any](ctx context.Context, c *Contract, ec Caller, block *big.Int, method string, args ...interface{}) (T, error) {
	var wrap struct{ V T }
	in, err := c.abi.Pack(method, args...)
	if err != nil {
		return wrap.V, fmt.Errorf("evmread: pack %s: %w", method, err)
	}
	out, err := ec.CallContract(ctx, gethereum.CallMsg{To: &c.addr, Data: in}, block)
	if err != nil {
		return wrap.V, fmt.Errorf("evmread: eth_call %s @ %s: %w", method, c.addr.Hex(), err)
	}
	if err := c.abi.UnpackIntoInterface(&wrap, method, out); err != nil {
		return wrap.V, fmt.Errorf("evmread: unpack %s: %w", method, err)
	}
	return wrap.V, nil
}

// Bounded wraps a read-only Caller and fails after `max` CallContract calls, bounding
// the eth_call fan-out of a SINGLE logical request so one request cannot amplify into an
// unbounded burst of upstream calls. It forwards the non-amplifying reads
// (ChainID/BlockNumber/HeaderByNumber) unchanged. max <= 0 disables the ceiling.
//
// Composing over Caller (not extending it) keeps the ceiling a pure wrapper: it adds a
// counter on the one amplifying verb and is otherwise transparent. A fresh Bounded per
// request gives each request an independent budget.
type Bounded struct {
	ec    Caller
	max   int
	calls atomic.Int64
}

// NewBounded returns a Caller that allows at most `max` CallContract calls before
// failing the (max+1)th. max <= 0 disables the ceiling (unbounded passthrough).
func NewBounded(ec Caller, max int) *Bounded {
	return &Bounded{ec: ec, max: max}
}

// Calls reports how many CallContract calls have been made through this wrapper.
func (b *Bounded) Calls() int64 { return b.calls.Load() }

func (b *Bounded) CallContract(ctx context.Context, call gethereum.CallMsg, block *big.Int) ([]byte, error) {
	if b.max > 0 {
		if n := b.calls.Add(1); n > int64(b.max) {
			return nil, fmt.Errorf("evmread: per-request eth_call ceiling exceeded (%d) — narrow the query (smaller limit/range)", b.max)
		}
	}
	return b.ec.CallContract(ctx, call, block)
}

func (b *Bounded) ChainID(ctx context.Context) (*big.Int, error) { return b.ec.ChainID(ctx) }

func (b *Bounded) BlockNumber(ctx context.Context) (uint64, error) { return b.ec.BlockNumber(ctx) }

func (b *Bounded) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	return b.ec.HeaderByNumber(ctx, n)
}
