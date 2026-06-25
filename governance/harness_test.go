// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Test harness — OPTION B, done with the REAL EVM (not canned values).
//
// The in-process `simulated` backend in THIS geth checkout is broken: its own
// TestNewBackend panics in node.Start -> eth.setupDiscovery (p2pServer.LocalNode()
// is nil in the NoDiscovery path — a fork regression). Rather than patch upstream
// geth, the harness drives the contracts on a real EVM via core/vm/runtime: a
// persistent state.StateDB seeded with the REAL compiled contract bytecode
// (testdata/*.json copied from standard/out). runtime.Create runs each real
// constructor; runtime.Call runs the real Solidity for both state-mutating ops and
// read-only eth_calls. So the parity tests compare MCP output against what the REAL
// getRound/getThought/valueOf actually return — full Solidity execution, not a fake
// table.
//
// The harness exposes an evmChain that satisfies the package's read-only EthCaller
// (CallContract/ChainID/BlockNumber/HeaderByNumber), so the MCP tools read the exact
// chain the harness drove. The HARNESS legitimately deploys and sends mutating calls
// to set up state — that is test scaffolding, NOT the MCP library (whose read-only
// invariant is asserted over its own non-test source by TestMCPReadOnlyToolsCannotSubmitTx).

package governance

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/accounts/abi"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/common/hexutil"
	"github.com/luxfi/geth/core/state"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm/runtime"
	"github.com/luxfi/geth/params"

	gethereum "github.com/luxfi/geth"

	"github.com/luxfi/mcp"
)

// artifact is the subset of a foundry build artifact we load.
type artifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

func loadArtifact(t *testing.T, name string) (abi.ABI, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read artifact %s: %v", name, err)
	}
	var a artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("parse artifact %s: %v", name, err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(a.ABI)))
	if err != nil {
		t.Fatalf("parse abi %s: %v", name, err)
	}
	code, err := hexutil.Decode(a.Bytecode.Object)
	if err != nil {
		t.Fatalf("decode bytecode %s: %v", name, err)
	}
	return parsed, code
}

// boundContract pairs a parsed ABI with the address the harness deployed it at, for
// harness-side reads/writes (INDEPENDENT of the MCP package's hand-written ABI).
type boundContract struct {
	abi  abi.ABI
	addr common.Address
}

// evmChain is a real-EVM test chain: a persistent StateDB, the real deployed
// contracts, and a block counter. It implements the package's EthCaller.
type evmChain struct {
	t         *testing.T
	cfg       *params.ChainConfig
	st        *state.StateDB
	blockNum  uint64
	blockTime uint64
	chainID   *big.Int
	deployer  common.Address
	gasLimit  uint64
}

var _ EthCaller = (*evmChain)(nil)

// newEVMChain builds the chain, funds the deployer + operator keys, and deploys the
// four governance contracts (Governor first; Params/Reputation reference it).
func newEVMChain(t *testing.T, operatorKeys []*ecdsa.PrivateKey) (*evmChain, *chainEnv) {
	t.Helper()
	st, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("new statedb: %v", err)
	}
	c := &evmChain{
		t:         t,
		cfg:       params.AllDevChainProtocolChanges,
		st:        st,
		blockNum:  1,
		blockTime: 1_700_000_000,
		chainID:   new(big.Int).Set(params.AllDevChainProtocolChanges.ChainID),
		gasLimit:  120_000_000,
	}

	deployerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("gen deployer: %v", err)
	}
	c.deployer = addrOf(deployerKey)
	c.fund(c.deployer)
	for _, k := range operatorKeys {
		c.fund(addrOf(k))
	}

	env := &chainEnv{t: t, c: c, deployerKey: deployerKey}
	env.deployAll()
	return c, env
}

func (c *evmChain) fund(a common.Address) {
	c.st.SetBalance(a, uint256.MustFromBig(ethers(1_000_000)), tracing.BalanceChangeUnspecified)
}

// getHashFn supplies blockhash(n): a deterministic non-zero hash for PAST blocks
// (n < current), zero for the current/future block. AIParams seeds its committee
// with blockhash(openBlock), available only once a later block exists — this models
// that exactly.
func (c *evmChain) getHashFn(n uint64) common.Hash {
	if n >= c.blockNum {
		return common.Hash{}
	}
	return common.BytesToHash(crypto.Keccak256([]byte(fmt.Sprintf("block-%d", n))))
}

// runtimeCfg builds the runtime.Config for the CURRENT block from `origin`.
func (c *evmChain) runtimeCfg(origin common.Address) *runtime.Config {
	return &runtime.Config{
		ChainConfig: c.cfg,
		Origin:      origin,
		State:       c.st,
		BlockNumber: new(big.Int).SetUint64(c.blockNum),
		Time:        c.blockTime,
		GasLimit:    c.gasLimit,
		GasPrice:    big.NewInt(0),
		Value:       big.NewInt(0),
		BaseFee:     big.NewInt(0),
		Difficulty:  big.NewInt(0),
		GetHashFn:   c.getHashFn,
	}
}

// deploy runs a real constructor and returns the deployed address. The deployer's
// nonce is bumped first so successive CREATE addresses don't collide.
func (c *evmChain) deploy(code []byte) common.Address {
	cfg := c.runtimeCfg(c.deployer)
	_, addr, _, err := runtime.Create(code, cfg)
	if err != nil {
		c.t.Fatalf("deploy: %v", err)
	}
	if len(c.st.GetCode(addr)) == 0 {
		c.t.Fatalf("deploy: no runtime code at %s", addr.Hex())
	}
	// Bump nonce so the next CREATE uses a fresh address.
	c.st.SetNonce(c.deployer, c.st.GetNonce(c.deployer)+1, tracing.NonceChangeUnspecified)
	return addr
}

// sendTx runs a state-mutating call from `from` to `to`, persisting state changes.
// A revert fails the test (mirrors a mined tx that must succeed). value is wei.
func (c *evmChain) sendTx(from common.Address, to common.Address, data []byte, value *big.Int) {
	cfg := c.runtimeCfg(from)
	if value != nil {
		cfg.Value = value
	}
	_, _, err := runtime.Call(to, data, cfg)
	if err != nil {
		c.t.Fatalf("sendTx -> %s reverted: %v", to.Hex(), err)
	}
	// Each tx advances the chain by one block (and the clock), as a real chain would.
	c.mine()
}

// mine advances the block number and clock. Empty mining (no tx) is used to make a
// future block exist so blockhash(openBlock) becomes available.
func (c *evmChain) mine() {
	c.st.Finalise(true)
	c.blockNum++
	c.blockTime += 12
}

// advanceBlocks mines `n` empty blocks (advances number + clock without a tx).
func (c *evmChain) advanceBlocks(n int) {
	for i := 0; i < n; i++ {
		c.mine()
	}
}

// advanceSeconds jumps the clock forward (to pass a voting deadline) and mines.
func (c *evmChain) advanceSeconds(secs uint64) {
	c.blockTime += secs
	c.mine()
}

// ---- EthCaller (the read-only surface the MCP server consumes) ----

// CallContract executes a read-only eth_call: it snapshots the StateDB, runs the
// call, and reverts so a view cannot mutate state. blockNumber is ignored (the
// in-memory chain has only the latest state) — matching how the tools call at HEAD.
func (c *evmChain) CallContract(_ context.Context, call gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	if call.To == nil {
		return nil, fmt.Errorf("evmChain: nil To in eth_call")
	}
	snap := c.st.Snapshot()
	cfg := c.runtimeCfg(call.From)
	ret, _, err := runtime.Call(*call.To, call.Data, cfg)
	c.st.RevertToSnapshot(snap)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (c *evmChain) ChainID(_ context.Context) (*big.Int, error) {
	return new(big.Int).Set(c.chainID), nil
}

func (c *evmChain) BlockNumber(_ context.Context) (uint64, error) {
	return c.blockNum, nil
}

// HeaderByNumber returns a synthetic header for the requested height (nil = head).
// Its Hash() must equal getHashFn for the SAME height so ChainObservation.Verify's
// reorg check is consistent: we set Number/Time and derive a deterministic root such
// that header.Hash() == the canonical hash the harness would report. To keep the two
// in lockstep, the header hash is taken from getHashFn for past blocks and a stable
// head hash for the current block.
func (c *evmChain) HeaderByNumber(_ context.Context, number *big.Int) (*types.Header, error) {
	n := c.blockNum
	if number != nil {
		n = number.Uint64()
	}
	return c.syntheticHeader(n), nil
}

// syntheticHeader builds a header whose Hash() is deterministic per height. We encode
// the height into the Extra field so types.Header.Hash() (keccak of the RLP) is a
// pure, stable function of the height — the observation's blockHash is then stable
// and the reorg check (re-read the same height, compare hash) is meaningful.
func (c *evmChain) syntheticHeader(n uint64) *types.Header {
	h := &types.Header{
		Number: new(big.Int).SetUint64(n),
		Time:   c.headerTime(n),
		Extra:  []byte(fmt.Sprintf("aivm-mcp-test-block-%d", n)),
	}
	return h
}

// headerTime maps a height to the timestamp it had. The current block uses the live
// clock; past blocks reconstruct (blockTime - 12*(blockNum-n)).
func (c *evmChain) headerTime(n uint64) uint64 {
	if n >= c.blockNum {
		return c.blockTime
	}
	return c.blockTime - 12*(c.blockNum-n)
}

// ---- harness-side reads (independent decode path) ----

// readStruct is the harness-side INDEPENDENT struct decode (full artifact ABI),
// using the same single-output wrapper geth requires (see callStruct in abi.go).
func readStruct[T any](t *testing.T, c *evmChain, b boundContract, method string, args ...interface{}) T {
	t.Helper()
	var wrap struct{ V T }
	in, err := b.abi.Pack(method, args...)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	ret, err := c.CallContract(context.Background(), gethereum.CallMsg{To: &b.addr, Data: in}, nil)
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	if err := b.abi.UnpackIntoInterface(&wrap, method, ret); err != nil {
		t.Fatalf("unpack %s: %v", method, err)
	}
	return wrap.V
}

// callViewValues unpacks into a []interface{} (for non-struct returns).
func (c *evmChain) callViewValues(b boundContract, method string, args ...interface{}) []interface{} {
	in, err := b.abi.Pack(method, args...)
	if err != nil {
		c.t.Fatalf("pack %s: %v", method, err)
	}
	ret, err := c.CallContract(context.Background(), gethereum.CallMsg{To: &b.addr, Data: in}, nil)
	if err != nil {
		c.t.Fatalf("call %s: %v", method, err)
	}
	m := b.abi.Methods[method]
	vals, err := m.Outputs.Unpack(ret)
	if err != nil {
		c.t.Fatalf("unpack %s: %v", method, err)
	}
	return vals
}

// ----------------------------------------------------------------------------
// chainEnv — the high-level driver the tests use (open/settle rounds & thoughts).
// ----------------------------------------------------------------------------

type chainEnv struct {
	t           *testing.T
	c           *evmChain
	deployerKey *ecdsa.PrivateKey

	params   boundContract
	governor boundContract
	registry boundContract
	rep      boundContract
}

func (e *chainEnv) cli() EthCaller { return e.c }

func (e *chainEnv) deployAll() {
	t := e.t
	govABI, govCode := loadArtifact(t, "AIGovernor.json")
	paramABI, paramCode := loadArtifact(t, "AIParams.json")
	regABI, regCode := loadArtifact(t, "AIThoughtRegistry.json")
	repABI, repCode := loadArtifact(t, "AIReputation.json")

	// AIGovernor(minBond=1, deregisterCooldown=0, rewardPerThought=0, openFee=0,
	// treasury=0, keyValuePairs=0). openFee==0 lets treasury be zero.
	govAddr := e.deployWithCtor(govABI, govCode,
		big.NewInt(1), uint64(0), big.NewInt(0), big.NewInt(0), common.Address{}, common.Address{})
	e.governor = boundContract{abi: govABI, addr: govAddr}

	// AIParams(governor, treasury=0, openFee=0, proposalFee=0).
	paramAddr := e.deployWithCtor(paramABI, paramCode, govAddr, common.Address{}, big.NewInt(0), big.NewInt(0))
	e.params = boundContract{abi: paramABI, addr: paramAddr}

	// AIThoughtRegistry(admin=deployer).
	regAddr := e.deployWithCtor(regABI, regCode, e.c.deployer)
	e.registry = boundContract{abi: regABI, addr: regAddr}

	// AIReputation(governor, alphaBps=2000).
	repAddr := e.deployWithCtor(repABI, repCode, govAddr, uint32(2000))
	e.rep = boundContract{abi: repABI, addr: repAddr}
}

// deployWithCtor packs constructor args, appends to creation bytecode, and deploys.
func (e *chainEnv) deployWithCtor(a abi.ABI, code []byte, args ...interface{}) common.Address {
	packed, err := a.Pack("", args...)
	if err != nil {
		e.t.Fatalf("pack ctor: %v", err)
	}
	return e.c.deploy(append(append([]byte{}, code...), packed...))
}

// mcpSurface builds the governance Surface reading THIS chain through the EthCaller.
func (e *chainEnv) mcpSurface() *Surface {
	g, err := NewWithCaller(e.c, Config{
		AIParams:          e.params.addr,
		AIGovernor:        e.governor.addr,
		AIThoughtRegistry: e.registry.addr,
		AIReputation:      e.rep.addr,
	})
	if err != nil {
		e.t.Fatalf("new governance surface: %v", err)
	}
	return g
}

// mcpServer wraps the governance Surface in the shared mcp transport, the way production
// does (mcp.Serve(ctx, in, out, governance.New(cfg))). Returns the *mcp.Server whose
// CallTool/Serve/Tools the tests exercise.
func (e *chainEnv) mcpServer() *mcp.Server {
	srv, err := mcp.NewServer(e.mcpSurface())
	if err != nil {
		e.t.Fatalf("new mcp server: %v", err)
	}
	return srv
}

// ---- AIParams round driving ----

func (e *chainEnv) registerOperator(key *ecdsa.PrivateKey) {
	in, err := e.governor.abi.Pack("registerOperator")
	if err != nil {
		e.t.Fatalf("pack registerOperator: %v", err)
	}
	e.c.sendTx(addrOf(key), e.governor.addr, in, big.NewInt(1)) // minBond = 1 wei
}

const oneHour = uint64(3600)

// openRound opens an AIParams value round and returns its roundId. n == operator
// population so the sortition committee is the WHOLE set (size>=population ⇒ every
// registered operator is selected), making the round deterministic to drive.
func (e *chainEnv) openRound(spec [32]byte, knobKey string, lo, hi *big.Int, n uint8) *big.Int {
	roundID := e.callParams("roundCount")[0].(*big.Int)
	threshold := n/2 + 1
	var zero [32]byte
	in, err := e.params.abi.Pack("open", spec, zero, knobKey, lo, hi, n, threshold, oneHour)
	if err != nil {
		e.t.Fatalf("pack open: %v", err)
	}
	e.c.sendTx(e.c.deployer, e.params.addr, in, nil)
	return roundID
}

// proposalDigest mirrors AIParams.proposalDigest (packed encoding).
func (e *chainEnv) proposalDigest(roundID *big.Int, op common.Address, spec [32]byte, value *big.Int, bucket uint16, evidence [32]byte) []byte {
	domain := crypto.Keccak256([]byte("hanzo/thinking-parameters/proposal/v1"))
	packed := concat(domain, leftPad32(e.c.chainID.Bytes()), e.params.addr.Bytes(),
		leftPad32(roundID.Bytes()), spec[:], leftPad32(value.Bytes()), u16be(bucket), evidence[:], op.Bytes())
	return crypto.Keccak256(packed)
}

func (e *chainEnv) submitProposal(key *ecdsa.PrivateKey, roundID *big.Int, spec [32]byte, value *big.Int, bucket uint16) {
	op := addrOf(key)
	var evidence [32]byte
	sig := e.sign(key, e.proposalDigest(roundID, op, spec, value, bucket, evidence))
	in, err := e.params.abi.Pack("submitProposal", roundID, value, bucket, evidence, sig)
	if err != nil {
		e.t.Fatalf("pack submitProposal: %v", err)
	}
	e.c.sendTx(op, e.params.addr, in, nil)
}

func (e *chainEnv) settleRound(roundID *big.Int) {
	in, err := e.params.abi.Pack("settle", roundID)
	if err != nil {
		e.t.Fatalf("pack settle: %v", err)
	}
	e.c.sendTx(e.c.deployer, e.params.addr, in, nil)
}

func (e *chainEnv) callParams(method string, args ...interface{}) []interface{} {
	return e.c.callViewValues(e.params, method, args...)
}

// ---- AIGovernor thought driving ----

func (e *chainEnv) openThought(spec [32]byte, knobKey string, n uint8) *big.Int {
	taskID := e.c.callViewValues(e.governor, "taskCount")[0].(*big.Int)
	threshold := n/2 + 1
	var zero [32]byte
	in, err := e.governor.abi.Pack("openThought", spec, zero, zero, n, threshold, oneHour, knobKey)
	if err != nil {
		e.t.Fatalf("pack openThought: %v", err)
	}
	e.c.sendTx(e.c.deployer, e.governor.addr, in, nil)
	return taskID
}

// verdictDigest mirrors AIGovernor._verdictDigest (packed encoding).
func (e *chainEnv) verdictDigest(taskID *big.Int, op common.Address, spec [32]byte, vote uint8, bucket uint16, evidence [32]byte) []byte {
	domain := crypto.Keccak256([]byte("hanzo/thinking-governor/verdict/v1"))
	packed := concat(domain, leftPad32(e.c.chainID.Bytes()), e.governor.addr.Bytes(),
		leftPad32(taskID.Bytes()), spec[:], []byte{vote}, u16be(bucket), evidence[:], op.Bytes())
	return crypto.Keccak256(packed)
}

func (e *chainEnv) submitVerdict(key *ecdsa.PrivateKey, taskID *big.Int, spec [32]byte, vote uint8, bucket uint16) {
	op := addrOf(key)
	var evidence [32]byte
	sig := e.sign(key, e.verdictDigest(taskID, op, spec, vote, bucket, evidence))
	in, err := e.governor.abi.Pack("submitVerdict", taskID, vote, bucket, evidence, sig)
	if err != nil {
		e.t.Fatalf("pack submitVerdict: %v", err)
	}
	e.c.sendTx(op, e.governor.addr, in, nil)
}

func (e *chainEnv) settleThought(taskID *big.Int) {
	in, err := e.governor.abi.Pack("settle", taskID)
	if err != nil {
		e.t.Fatalf("pack settle: %v", err)
	}
	e.c.sendTx(e.c.deployer, e.governor.addr, in, nil)
}

// sign produces a secp256k1 signature over `digest` with v in {27,28} (the form the
// contracts' OZ ECDSA expects; Go crypto.Sign yields {0,1}, so add 27).
func (e *chainEnv) sign(key *ecdsa.PrivateKey, digest []byte) []byte {
	sig, err := crypto.Sign(digest, key)
	if err != nil {
		e.t.Fatalf("sign: %v", err)
	}
	sig[64] += 27
	return sig
}

// ----------------------------------------------------------------------------
// byte helpers (packed-encoding parity with abi.encodePacked) + misc
// ----------------------------------------------------------------------------

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func u16be(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func ethers(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }

// addrOf derives the geth common.Address for a key. luxfi/crypto.PubkeyToAddress
// returns its OWN common.Address ([20]byte under a different package); we bridge
// through the raw bytes — both are 20-byte big-endian, byte-identical.
func addrOf(key *ecdsa.PrivateKey) common.Address {
	a := crypto.PubkeyToAddress(key.PublicKey)
	return common.BytesToAddress(a[:])
}

// specHash is a deterministic test model-spec hash from a label.
func specHash(label string) [32]byte {
	var s [32]byte
	copy(s[:], crypto.Keccak256([]byte(label)))
	return s
}

// genKeys returns n freshly generated keys, sorted by address ascending for a stable
// operator ordering across runs.
func genKeys(t *testing.T, n int) []*ecdsa.PrivateKey {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, 0, n)
	for i := 0; i < n; i++ {
		k, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return addrOf(keys[i]).Hex() < addrOf(keys[j]).Hex()
	})
	return keys
}
