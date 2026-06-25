// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mcp is the domain-agnostic, READ-ONLY MCP (Model Context Protocol) transport
// for the Lux governance stack — the "sensory layer" an operator-LLM uses to query
// chain facts during deliberation.
//
// One transport, many surfaces. This package owns the JSON-RPC 2.0 over stdio loop, the
// tool dispatch guards (per-call timeout, panic recover, request line cap), and the
// ChainObservation value every read returns. It knows NOTHING about any specific chain
// contract: a domain contributes a Surface — a []Tool — and Serve indexes and dispatches
// them. (Rich Hickey decomplecting: the transport is "run named read tools over stdio";
// a tool is a VALUE carrying its own Read closure; the chain-reading mechanics live in
// github.com/luxfi/mcp/evmread; a domain like governance/ supplies only the tools.)
//
// READ-ONLY BY CONSTRUCTION. The transport links no signing or transaction-submission
// primitive. The only chain access a tool can do is through evmread.Caller (the
// read-only eth_call plus header/chainId/blockNumber readers); there is no
// SendTransaction, no keyed transactor, no eth_sendRawTransaction anywhere in this
// module. The read-only gate (readonly_test.go) scans the WHOLE module to assert this,
// and asserts evmread.Caller's method set is exactly the four read verbs.
//
// Transport is JSON-RPC 2.0 over stdio (newline-delimited): Serve reads requests from an
// io.Reader and writes responses to an io.Writer. Methods: initialize, tools/list,
// tools/call. Standard library only — no external MCP SDK.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ServerName / ServerVersion are returned in the initialize handshake.
const (
	ServerName    = "lux-mcp"
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

	// defaultCallTimeout bounds one tools/call dispatch end-to-end (reaching every chain
	// read). Long enough for a healthy RPC, short enough that one hung call cannot wedge
	// the stdio loop (the next request is still served once the budget elapses).
	defaultCallTimeout = 20 * time.Second
)

// Tool is one read tool: a VALUE carrying its descriptor AND its handler. Collapsing the
// old parallel name->schema + name->handler maps into a single Tool value is the core
// decomplect — a tool is a thing, not two coordinated table entries.
//
// Read runs the tool: it receives the request context (already bounded by the per-call
// timeout) and the decoded args, and returns (value, observation, error). value is any
// JSON-serializable result; observation is the verifiable ChainObservation of the exact
// reads the tool performed (may be nil for a tool that observes nothing); error is a
// tool-level failure surfaced to the caller. Read may issue read-only chain calls; it can
// never send a transaction (the only chain seam it is given is evmread.Caller, captured
// by the domain in the closure — the transport never hands it a write capability).
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]interface{}
	Read        func(ctx context.Context, args map[string]interface{}) (interface{}, *ChainObservation, error)
}

// Surface is a domain's contribution to the transport: a set of read tools. governance/
// is one Surface; a composition test supplies another. Serve runs any number of them
// behind the one transport.
type Surface interface {
	Tools() []Tool
}

// Server is the read-only MCP transport over one or more Surfaces. It owns only the tool
// index and the dispatch budgets; it has no chain dependency of its own (each tool
// captures its own read seam). It exposes NO method that can sign or submit a tx.
type Server struct {
	tools map[string]Tool
	descs []Tool

	// callTimeout bounds one tools/call dispatch. Defaulted in newServer; overridable
	// in-package (tests shrink it).
	callTimeout time.Duration
}

// Serve runs the stdio JSON-RPC loop over the given surfaces until EOF or ctx
// cancellation. It is the ONE transport entry point: it builds a name->Tool index across
// ALL surfaces (erroring on a duplicate tool name) and dispatches each request to
// initialize / tools/list / tools/call.
func Serve(ctx context.Context, in io.Reader, out io.Writer, surfaces ...Surface) error {
	s, err := newServer(surfaces...)
	if err != nil {
		return err
	}
	return s.Serve(ctx, in, out)
}

// Serve runs the stdio JSON-RPC loop on an already-built Server (the seam for callers
// that need to construct the server first, e.g. to observe Tools() or tune budgets). The
// package-level Serve builds a Server and calls this.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return s.serve(ctx, in, out)
}

// NewServer builds the transport over the given surfaces without starting the stdio loop.
// It is the seam in-process callers and tests use: CallTool dispatches a single tool with
// the same guards Serve applies. Returns an error on a duplicate tool name across
// surfaces.
func NewServer(surfaces ...Surface) (*Server, error) {
	return newServer(surfaces...)
}

func newServer(surfaces ...Surface) (*Server, error) {
	s := &Server{
		tools:       map[string]Tool{},
		callTimeout: defaultCallTimeout,
	}
	for _, sf := range surfaces {
		for _, t := range sf.Tools() {
			if strings.TrimSpace(t.Name) == "" {
				return nil, errors.New("mcp: surface registered a tool with an empty name")
			}
			if t.Read == nil {
				return nil, fmt.Errorf("mcp: tool %q has a nil Read handler", t.Name)
			}
			if _, dup := s.tools[t.Name]; dup {
				return nil, fmt.Errorf("mcp: duplicate tool name %q across surfaces", t.Name)
			}
			s.tools[t.Name] = t
			s.descs = append(s.descs, t)
		}
	}
	return s, nil
}

// ----------------------------------------------------------------------------
// JSON-RPC 2.0 envelope (stdio).
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

// toolDescriptor is the wire shape of a tool in tools/list (the MCP `inputSchema` key).
// It is projected from a Tool value so the handler closure is never serialized.
type toolDescriptor struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// content is one MCP tool-result content block. Tool results are returned as a single
// text block carrying the JSON-encoded result value (and, when present, the observation).
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// serve runs the stdio JSON-RPC loop: it reads newline-delimited JSON-RPC requests from
// `in` and writes responses to `out` until EOF or ctx cancellation. Notifications (no id)
// get no response, per the JSON-RPC spec.
func (s *Server) serve(ctx context.Context, in io.Reader, out io.Writer) error {
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

// handle parses one request line and routes it. Returns the response to write, or nil
// for notifications (requests without an id).
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
		return okResp(req.ID, map[string]interface{}{"tools": s.toolDescriptors()})
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

// toolDescriptors projects the registered tools to their wire descriptors (name +
// description + inputSchema), stripping the handler closures.
func (s *Server) toolDescriptors() []toolDescriptor {
	out := make([]toolDescriptor, 0, len(s.descs))
	for _, t := range s.descs {
		out = append(out, toolDescriptor{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out
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
	result, obs, err := s.dispatch(ctx, p.Name, p.Arguments)
	if err != nil {
		// Tool errors (incl. timeout and recovered panics) are returned as a successful
		// MCP response with isError=true so the client model sees the failure text (per
		// MCP tool-result convention), not as a JSON-RPC protocol error, and the stdio
		// loop keeps serving the next request.
		return okResp(id, map[string]interface{}{
			"content": []content{{Type: "text", Text: err.Error()}},
			"isError": true,
		})
	}
	// Embed the value AND (when present) the verifiable observation in the tool-result
	// content, so a caller can read the value and independently re-derive/verify the
	// observation hash against the chain state it claims.
	payload := map[string]interface{}{"value": result}
	if obs != nil {
		payload["observation"] = observationView(obs)
	}
	encoded, merr := json.Marshal(payload)
	if merr != nil {
		return errResp(id, codeInternalError, "encode result: "+merr.Error())
	}
	return okResp(id, map[string]interface{}{
		"content": []content{{Type: "text", Text: string(encoded)}},
	})
}

// observationView is the JSON shape of an observation embedded in a tool result: the
// block context, the tool name, the sorted/deduped reads, and the binding hash. A caller
// re-derives the hash from these reads via NewObservation/Hash to check the binding.
func observationView(o *ChainObservation) map[string]interface{} {
	return map[string]interface{}{
		"chainId":     bigString(o.ChainID),
		"blockNumber": o.BlockNumber,
		"blockHash":   o.BlockHash.Hex(),
		"timestamp":   o.Timestamp,
		"tool":        o.Tool,
		"reads":       o.Reads,
		"hash":        o.Hash().Hex(),
	}
}

// dispatch runs ONE tool with the transport guards: a per-call timeout (so a hung
// upstream RPC cannot wedge the server) and a panic recover (so a single bad call becomes
// one error, never a whole-server crash). The handler reads only — these guards add no
// write capability. Domain-specific limits (e.g. a per-request eth_call ceiling) live in
// the domain's Read closure, not here, so the transport stays chain-agnostic. Used by
// both the stdio path and CallTool, so the invariants hold no matter how a tool is
// invoked.
func (s *Server) dispatch(parent context.Context, name string, args map[string]interface{}) (result interface{}, obs *ChainObservation, err error) {
	t, ok := s.tools[name]
	if !ok {
		return nil, nil, fmt.Errorf("mcp: unknown tool %q", name)
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
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mcp: tool %q panicked: %v", name, r)
			result = nil
			obs = nil
		}
	}()
	return t.Read(ctx, args)
}

// CallTool runs a read tool directly (bypassing the stdio envelope) and returns the
// decoded result VALUE. Exposed for in-process callers and tests; it is read-only like
// every tool. The observation is dropped here (in-process callers that want it can build
// it from the same reads); CallToolObserved returns both. Unknown tool names error.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	v, _, err := s.dispatch(ctx, name, args)
	return v, err
}

// CallToolObserved runs a read tool and returns BOTH its value and the observation it
// produced (nil when the tool observes nothing). Exposed for callers that bind the
// observation into a verdict.
func (s *Server) CallToolObserved(ctx context.Context, name string, args map[string]interface{}) (interface{}, *ChainObservation, error) {
	return s.dispatch(ctx, name, args)
}

// Tools returns the descriptors for the registered read tools (the tools/list surface).
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
