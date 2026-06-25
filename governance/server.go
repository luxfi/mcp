// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package governance is a Surface of eight READ-ONLY governance tools for the Lux AIVM
// (A-Chain) governance stack — the chain-fact queries an operator-LLM uses during
// deliberation. It contributes []mcp.Tool to the shared, domain-agnostic transport in
// github.com/luxfi/mcp; it does the chain reads through github.com/luxfi/mcp/evmread.
//
// READ-ONLY BY CONSTRUCTION. This package holds no private key and links no signing or
// transaction-submission primitive: every chain access goes through evmread.Caller (the
// read-only eth_call) or the header/chainId/blockNumber readers. There is no
// SendTransaction, no keyed transactor, no eth_sendRawTransaction anywhere in this
// package — and it imports no go-ethereum transactor surface at all (the read-only gate
// in luxfi/mcp scans the whole module to assert this; evmread is the SOLE geth importer).
// Verdicts are produced and submitted by the operator through the normal AIGovernor tx
// path, NOT through this server.
//
// Orthogonal split (Rich Hickey): mcp READS over stdio. evmread READS the chain.
// governance KNOWS the contracts. AIGovernor settles votes; AIParams stores knobs;
// AIThoughtRegistry records receipts; AIReputation scores operators — this package
// depends on NONE of their write paths.
package governance

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/ethclient"

	"github.com/luxfi/mcp"
	"github.com/luxfi/mcp/evmread"
)

// EthCaller is the read-only chain surface this package consumes. It is an alias for
// evmread.Caller so the production *ethclient.Client and the in-process test backend both
// satisfy it without this package naming geth's transactor surface.
type EthCaller = evmread.Caller

// defaultMaxCallsPerRequest caps the eth_calls one tools/call may issue, so a single line
// cannot amplify into thousands of upstream calls. param_history at the limit cap (256
// rounds x 2 calls + count ~= 513) and pending_operations both stay well under this; it is
// the hard backstop, not the normal path. The ceiling is THIS package's concern (it knows
// its read patterns); the transport bounds time and crashes, not call count.
const defaultMaxCallsPerRequest = 1024

// Config holds the EVM RPC endpoint and the four deployed governance contract addresses.
// AIParams, AIGovernor are required (most tools need them); AIThoughtRegistry and
// AIReputation are required for receipt_lookup and the reputation reads respectively. All
// four are validated in New.
type Config struct {
	// EVMRPC is the governance EVM chain's RPC URL — an L1/L2/L3 EVM endpoint or a
	// …/ext/bc/C/rpc. Dialed read-only via ethclient.DialContext.
	EVMRPC string

	AIParams          common.Address
	AIGovernor        common.Address
	AIThoughtRegistry common.Address
	AIReputation      common.Address
}

// Surface is the read-only governance tool set. It owns a read-only evmread.Caller and the
// four bound view-contracts, and yields the eight tools via Tools(). It exposes NO method
// that can sign or submit a tx.
type Surface struct {
	ec evmread.Caller

	params   *evmread.Contract
	governor *evmread.Contract
	registry *evmread.Contract
	rep      *evmread.Contract

	// maxCallsPerRequest caps a single tool's eth_call fan-out (the per-request ceiling).
	// Defaulted in newSurface; overridable in-package (tests shrink it).
	maxCallsPerRequest int
}

// Ensure the concrete Surface satisfies the transport's Surface contract.
var _ mcp.Surface = (*Surface)(nil)

// New dials the EVM RPC (read-only), binds the four contract view-ABIs, and returns the
// governance tool Surface. The dialed *ethclient.Client satisfies evmread.Caller; the
// production server reads the live chain through it. Returns an error if any address is
// zero or the dial fails.
func New(ctx context.Context, cfg Config) (mcp.Surface, error) {
	return NewWithDial(ctx, cfg)
}

// NewWithDial is New returning the concrete *Surface (for callers that need it). Most
// callers use New and treat it as an mcp.Surface.
func NewWithDial(ctx context.Context, cfg Config) (*Surface, error) {
	if cfg.EVMRPC == "" {
		return nil, errors.New("mcp: empty EVMRPC")
	}
	if err := validateAddrs(cfg); err != nil {
		return nil, err
	}
	ec, err := ethclient.DialContext(ctx, cfg.EVMRPC)
	if err != nil {
		return nil, fmt.Errorf("mcp: dial EVM RPC %s: %w", cfg.EVMRPC, err)
	}
	return newSurface(ec, cfg)
}

// NewWithCaller builds a Surface over an already-constructed read-only evmread.Caller and
// the contract addresses (no dial). This is the seam the in-process tests use to inject
// the simulated backend's Client; it carries no signing capability because evmread.Caller
// has none. Production callers use New.
func NewWithCaller(ec evmread.Caller, cfg Config) (*Surface, error) {
	if ec == nil {
		return nil, errors.New("mcp: nil EthCaller")
	}
	if err := validateAddrs(cfg); err != nil {
		return nil, err
	}
	return newSurface(ec, cfg)
}

func validateAddrs(cfg Config) error {
	if (cfg.AIParams == common.Address{}) {
		return errors.New("mcp: AIParams address is zero")
	}
	if (cfg.AIGovernor == common.Address{}) {
		return errors.New("mcp: AIGovernor address is zero")
	}
	if (cfg.AIThoughtRegistry == common.Address{}) {
		return errors.New("mcp: AIThoughtRegistry address is zero")
	}
	if (cfg.AIReputation == common.Address{}) {
		return errors.New("mcp: AIReputation address is zero")
	}
	return nil
}

func newSurface(ec evmread.Caller, cfg Config) (*Surface, error) {
	params, governor, registry, rep, err := bindContracts(cfg)
	if err != nil {
		return nil, err
	}
	return &Surface{
		ec:                 ec,
		params:             params,
		governor:           governor,
		registry:           registry,
		rep:                rep,
		maxCallsPerRequest: defaultMaxCallsPerRequest,
	}, nil
}

// bounded returns a fresh per-request read ceiling over the surface's caller. A NEW
// wrapper per dispatch gives each tool call an independent eth_call budget without
// mutating shared state. The ceiling lives in evmread (a pure wrapper over the read
// verb); this package only chooses the limit and resets it by constructing a new wrapper.
func (g *Surface) bounded() evmread.Caller {
	return evmread.NewBounded(g.ec, g.maxCallsPerRequest)
}
