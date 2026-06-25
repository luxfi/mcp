// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mcp is a node-side, READ-ONLY governance MCP (Model Context Protocol)
// server for the Lux AIVM (A-Chain) governance stack — the "sensory layer" an
// operator-LLM uses to query chain facts during deliberation.
//
// READ-ONLY BY CONSTRUCTION. v1 exposes only the eight read tools below. The
// package holds no private key and links no signing or transaction-submission
// primitive: every chain access goes through EthCaller.CallContract (the read-only
// eth_call) or the header/chainId/blockNumber readers. There is no SendTransaction,
// no keyed transactor, no eth_sendRawTransaction anywhere in this package. Verdicts
// are produced and submitted by the operator through the normal AIGovernor tx path,
// NOT through this server. (TestMCPReadOnlyToolsCannotSubmitTx asserts this by
// scanning the package source for forbidden write tokens and by checking that
// tools/list returns exactly the eight read tools.)
//
// Orthogonal split (Rich Hickey): MCP READS the chain. AIGovernor settles votes.
// AIParams stores knobs. AIThoughtRegistry records receipts. AIReputation scores
// operators. This package depends on NONE of the write paths — it links only the
// read surface (EthCaller) and the hand-written view-function ABIs in abi.go. The
// EVM-call discipline mirrors chains/dexvm/registry/rpcverify: dial an EVM RPC,
// call view functions, keep JSON-RPC/consensus write deps out of the path.
//
// Transport is JSON-RPC 2.0 over stdio (newline-delimited): Serve reads requests
// from an io.Reader and writes responses to an io.Writer. Methods: initialize,
// tools/list, tools/call. Standard library only — no external MCP SDK.
package governance

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync/atomic"
	"time"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/ethclient"
)

// ServerName / ServerVersion are returned in the initialize handshake.
const (
	ServerName    = "aivm-gov-mcp"
	ServerVersion = "1.0.0"
	// ProtocolVersion is the MCP protocol revision this server speaks.
	ProtocolVersion = "2024-11-05"
)

// Availability/safety bounds. These cap what a single stdio line can cost so one
// client (or one wedged upstream RPC) cannot exhaust the server.
const (
	// maxLineBytes bounds one JSON-RPC request line. MCP requests are tiny (a tool name
	// + a few scalar args), so 1 MiB is generous; a longer line is rejected as a parse
	// error WITHOUT buffering it whole (the reader stops at the cap and drains the rest).
	maxLineBytes = 1 << 20 // 1 MiB

	// defaultCallTimeout bounds one tools/call dispatch end-to-end (reaching every
	// eth_call). It mirrors the per-request budget in chains/dexvm/registry/rpcverify:
	// long enough for a healthy RPC, short enough that one hung call cannot wedge the
	// stdio loop (the next request is still served once the budget elapses).
	defaultCallTimeout = 20 * time.Second

	// defaultMaxCallsPerRequest caps the eth_calls one tools/call may issue, so a single
	// line cannot amplify into thousands of upstream calls. param_history at the limit
	// cap (256 rounds x 2 calls + count ~= 513) and pending_operations both stay well
	// under this; it is the hard backstop, not the normal path.
	defaultMaxCallsPerRequest = 1024
)

// Config holds the EVM RPC endpoint and the four deployed governance contract
// addresses. AIParams, AIGovernor are required (most tools need them);
// AIThoughtRegistry and AIReputation are required for receipt_lookup and the
// reputation reads respectively. All four are validated in New.
type Config struct {
	// EVMRPC is the governance EVM chain's RPC URL — an L1/L2/L3 EVM endpoint or a
	// …/ext/bc/C/rpc. Dialed read-only via ethclient.DialContext.
	EVMRPC string

	AIParams          common.Address
	AIGovernor        common.Address
	AIThoughtRegistry common.Address
	AIReputation      common.Address
}

// Server is the read-only governance MCP server. It owns a read-only EthCaller and
// the four bound view-ABIs. It exposes NO method that can sign or submit a tx.
type Server struct {
	ec EthCaller

	params   *boundABI
	governor *boundABI
	registry *boundABI
	rep      *boundABI

	tools map[string]toolHandler
	descs []Tool

	// callTimeout bounds one tools/call dispatch; maxCallsPerRequest caps its eth_calls.
	// Defaulted in newServer; overridable in-package (tests shrink them).
	callTimeout        time.Duration
	maxCallsPerRequest int
}

// toolHandler runs one read tool: bound as a method expression on *Server, it
// receives the server, the context, and the decoded args, and returns a
// JSON-serializable result (or an error). It may issue read-only eth_calls via the
// server's EthCaller; it can never send a transaction.
type toolHandler func(s *Server, ctx context.Context, args map[string]interface{}) (interface{}, error)

// New dials the EVM RPC (read-only) and binds the four contract view-ABIs. The
// dialed *ethclient.Client satisfies EthCaller; the production server reads the
// live chain through it. Returns an error if any address is zero or the dial fails.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.EVMRPC == "" {
		return nil, errors.New("mcp: empty EVMRPC")
	}
	if (cfg.AIParams == common.Address{}) {
		return nil, errors.New("mcp: AIParams address is zero")
	}
	if (cfg.AIGovernor == common.Address{}) {
		return nil, errors.New("mcp: AIGovernor address is zero")
	}
	if (cfg.AIThoughtRegistry == common.Address{}) {
		return nil, errors.New("mcp: AIThoughtRegistry address is zero")
	}
	if (cfg.AIReputation == common.Address{}) {
		return nil, errors.New("mcp: AIReputation address is zero")
	}
	ec, err := ethclient.DialContext(ctx, cfg.EVMRPC)
	if err != nil {
		return nil, fmt.Errorf("mcp: dial EVM RPC %s: %w", cfg.EVMRPC, err)
	}
	return newServer(ec, cfg)
}

// NewWithCaller builds a Server over an already-constructed read-only EthCaller and
// the contract addresses (no dial). This is the seam the in-process tests use to
// inject the simulated backend's Client; it carries no signing capability because
// EthCaller has none. Production callers use New.
func NewWithCaller(ec EthCaller, cfg Config) (*Server, error) {
	if ec == nil {
		return nil, errors.New("mcp: nil EthCaller")
	}
	return newServer(ec, cfg)
}

func newServer(ec EthCaller, cfg Config) (*Server, error) {
	params, err := newBoundABI(aiParamsABI, cfg.AIParams)
	if err != nil {
		return nil, err
	}
	governor, err := newBoundABI(aiGovernorABI, cfg.AIGovernor)
	if err != nil {
		return nil, err
	}
	registry, err := newBoundABI(aiThoughtRegistryABI, cfg.AIThoughtRegistry)
	if err != nil {
		return nil, err
	}
	rep, err := newBoundABI(aiReputationABI, cfg.AIReputation)
	if err != nil {
		return nil, err
	}
	s := &Server{
		ec:                 ec,
		params:             params,
		governor:           governor,
		registry:           registry,
		rep:                rep,
		callTimeout:        defaultCallTimeout,
		maxCallsPerRequest: defaultMaxCallsPerRequest,
	}
	s.tools, s.descs = registerTools()
	return s, nil
}

// boundedCaller wraps a read-only EthCaller and fails after `max` CallContract calls,
// bounding the eth_call fan-out of a SINGLE tools/call so one request cannot amplify
// into an unbounded burst of upstream calls. It forwards the non-amplifying reads
// (ChainID/BlockNumber/HeaderByNumber) unchanged. max <= 0 disables the ceiling.
type boundedCaller struct {
	ec    EthCaller
	max   int
	calls atomic.Int64
}

func newBoundedCaller(ec EthCaller, max int) *boundedCaller {
	return &boundedCaller{ec: ec, max: max}
}

func (b *boundedCaller) CallContract(ctx context.Context, call gethereum.CallMsg, block *big.Int) ([]byte, error) {
	if b.max > 0 {
		if n := b.calls.Add(1); n > int64(b.max) {
			return nil, fmt.Errorf("mcp: per-request eth_call ceiling exceeded (%d) — narrow the query (smaller limit/range)", b.max)
		}
	}
	return b.ec.CallContract(ctx, call, block)
}

func (b *boundedCaller) ChainID(ctx context.Context) (*big.Int, error) { return b.ec.ChainID(ctx) }
func (b *boundedCaller) BlockNumber(ctx context.Context) (uint64, error) {
	return b.ec.BlockNumber(ctx)
}
func (b *boundedCaller) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	return b.ec.HeaderByNumber(ctx, n)
}

// withBoundedCaller returns a shallow copy of s whose EthCaller is wrapped with a
// fresh per-request call ceiling. The copy shares the bound ABIs and tool map (all
// immutable after construction); only the read seam is swapped. This keeps each
// request's eth_call budget independent without mutating the shared server.
func (s *Server) withBoundedCaller() *Server {
	cp := *s
	cp.ec = newBoundedCaller(s.ec, s.maxCallsPerRequest)
	return &cp
}

// ----------------------------------------------------------------------------
// JSON-RPC 2.0 envelope (stdio). Mirrors the shapes in zap/mcp/bridge.go.
// ----------------------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes (subset of the spec used here).
const (
	codeParseError    = -32700
	codeInvalidReq    = -32600
	codeMethodNotFnd  = -32601
	codeInvalidParams = -32602
	codeInternalError = -32603
)

// Tool is the MCP tool descriptor (same shape as zap/mcp.Tool: ID, Name,
// Description, InputSchema with the `inputSchema` JSON key).
type Tool struct {
	ID          uint32                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// content is one MCP tool-result content block. Tool results are returned as a
// single text block carrying the JSON-encoded result value.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Serve runs the stdio JSON-RPC loop: it reads newline-delimited JSON-RPC requests
// from `in` and writes responses to `out` until EOF or ctx cancellation. Each request
// is dispatched to initialize / tools/list / tools/call. Notifications (no id, e.g.
// notifications/initialized) get no response, per the JSON-RPC spec.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer w.Flush()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, tooLong, err := readLimitedLine(r, maxLineBytes)
		if tooLong {
			// The request line exceeded the cap; we did NOT buffer it whole (the rest of
			// the line was drained). Reply with a parse error and keep serving — one
			// oversized line cannot OOM the server or kill the loop.
			if werr := writeJSONLine(w, errResp(nil, codeParseError, "request line exceeds maximum length")); werr != nil {
				return werr
			}
			if ferr := w.Flush(); ferr != nil {
				return ferr
			}
		} else if len(line) > 0 {
			trimmed := strings.TrimSpace(string(line))
			if trimmed != "" {
				if resp := s.handle(ctx, []byte(trimmed)); resp != nil {
					if werr := writeJSONLine(w, resp); werr != nil {
						return werr
					}
					if ferr := w.Flush(); ferr != nil {
						return ferr
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readLimitedLine reads one newline-terminated line but never buffers more than `max`
// bytes. If the line is longer than `max`, it returns tooLong=true with the partial
// bytes discarded (it drains the rest of the line so the NEXT read starts on a fresh
// line), so an adversarial multi-megabyte line cannot grow memory without bound. The
// returned error mirrors bufio.Reader.ReadBytes (io.EOF at stream end, possibly with a
// final unterminated line). A trailing '\n' is included in the returned slice when the
// line fit, matching the prior ReadBytes('\n') contract for the parse path.
func readLimitedLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	buf := make([]byte, 0, 256)
	for {
		var c byte
		c, err = r.ReadByte()
		if err != nil {
			return buf, false, err
		}
		if c == '\n' {
			buf = append(buf, c)
			return buf, false, nil
		}
		if len(buf) >= max {
			// Over the cap: stop buffering and drain to end-of-line (or EOF) so the loop
			// resynchronizes on the next line instead of mid-line.
			for {
				d, derr := r.ReadByte()
				if derr != nil {
					return nil, true, derr
				}
				if d == '\n' {
					return nil, true, nil
				}
			}
		}
		buf = append(buf, c)
	}
}

// handle parses one request line and routes it. Returns the response to write, or
// nil for notifications (requests without an id).
func (s *Server) handle(ctx context.Context, line []byte) *rpcResponse {
	var req rpcRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return errResp(nil, codeParseError, "parse error: "+err.Error())
	}
	// A request with no id is a notification — process side effects (none here) and
	// return nothing.
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"

	switch req.Method {
	case "initialize":
		if isNotification {
			return nil
		}
		return okResp(req.ID, s.initializeResult())
	case "notifications/initialized", "initialized":
		return nil
	case "tools/list":
		if isNotification {
			return nil
		}
		return okResp(req.ID, map[string]interface{}{"tools": s.descs})
	case "tools/call":
		if isNotification {
			return nil
		}
		return s.handleToolsCall(ctx, req.ID, req.Params)
	default:
		if isNotification {
			return nil
		}
		return errResp(req.ID, codeMethodNotFnd, "method not found: "+req.Method)
	}
}

func (s *Server) initializeResult() map[string]interface{} {
	return map[string]interface{}{
		"protocolVersion": ProtocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    ServerName,
			"version": ServerVersion,
		},
	}
}

// toolCallParams is the MCP tools/call params shape.
type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

func (s *Server) handleToolsCall(ctx context.Context, id json.RawMessage, raw json.RawMessage) *rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return errResp(id, codeInvalidParams, "invalid params: "+err.Error())
	}
	if _, ok := s.tools[p.Name]; !ok {
		return errResp(id, codeMethodNotFnd, "unknown tool: "+p.Name)
	}
	result, err := s.dispatch(ctx, p.Name, p.Arguments)
	if err != nil {
		// Tool errors (incl. timeout, call-ceiling, and recovered panics) are returned
		// as a successful MCP response with isError=true so the client model sees the
		// failure text (per MCP tool-result convention), not as a JSON-RPC protocol
		// error, and the stdio loop keeps serving the next request.
		return okResp(id, map[string]interface{}{
			"content": []content{{Type: "text", Text: err.Error()}},
			"isError": true,
		})
	}
	encoded, merr := json.Marshal(result)
	if merr != nil {
		return errResp(id, codeInternalError, "encode result: "+merr.Error())
	}
	return okResp(id, map[string]interface{}{
		"content": []content{{Type: "text", Text: string(encoded)}},
	})
}

// dispatch runs ONE tool with the request-scoped guards: a per-call timeout (so a hung
// upstream RPC cannot wedge the server), a per-request eth_call ceiling (so one line
// cannot amplify into thousands of calls), and a panic recover (so a single bad call
// becomes one error, never a whole-server crash). The handler reads only — these guards
// add no write capability. Used by both the stdio path and CallTool, so the invariants
// hold no matter how a tool is invoked.
func (s *Server) dispatch(parent context.Context, name string, args map[string]interface{}) (result interface{}, err error) {
	h, ok := s.tools[name]
	if !ok {
		return nil, fmt.Errorf("mcp: unknown tool %q", name)
	}
	if args == nil {
		args = map[string]interface{}{}
	}
	ctx := parent
	var cancel context.CancelFunc
	if s.callTimeout > 0 {
		ctx, cancel = context.WithTimeout(parent, s.callTimeout)
		defer cancel()
	}
	// Fresh per-request call ceiling on a shallow server copy (shared immutable ABIs).
	scoped := s.withBoundedCaller()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mcp: tool %q panicked: %v", name, r)
			result = nil
		}
	}()
	return h(scoped, ctx, args)
}

// CallTool runs a read tool directly (bypassing the stdio envelope) and returns the
// decoded result. Exposed for in-process callers and tests; it is read-only like
// every tool. Unknown tool names return an error.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	if _, ok := s.tools[name]; !ok {
		return nil, fmt.Errorf("mcp: unknown tool %q", name)
	}
	return s.dispatch(ctx, name, args)
}

// Tools returns the descriptors for the registered read tools (the tools/list
// surface). The slice is the canonical v1 surface — exactly eight read tools.
func (s *Server) Tools() []Tool { return s.descs }

func okResp(id json.RawMessage, result interface{}) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func errResp(id json.RawMessage, code int, msg string) *rpcResponse {
	return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcErr{Code: code, Message: msg}}
}

func writeJSONLine(w io.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}
