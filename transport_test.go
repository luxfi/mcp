// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// fakeSurface is a self-contained Surface for the transport tests: it carries an explicit
// tool list so the transport can be exercised WITHOUT any chain dependency (the transport
// is domain-agnostic — that is the whole point of the decomplect).
type fakeSurface struct{ tools []Tool }

func (f fakeSurface) Tools() []Tool { return f.tools }

// okTool returns a fixed value and no observation — the minimal well-behaved tool.
func okTool(name string) Tool {
	return Tool{
		Name:        name,
		Description: name,
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		Read: func(_ context.Context, _ map[string]interface{}) (interface{}, *ChainObservation, error) {
			return map[string]interface{}{"ok": true, "tool": name}, nil, nil
		},
	}
}

// blockingTool blocks until the dispatch context is cancelled (modeling a hung upstream
// RPC), then returns the context error — so the per-call timeout guard surfaces.
func blockingTool(name string) Tool {
	return Tool{
		Name:        name,
		Description: name,
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		Read: func(ctx context.Context, _ map[string]interface{}) (interface{}, *ChainObservation, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	}
}

// panicTool panics — the dispatch recover must turn it into one error, not a crash.
func panicTool(name string) Tool {
	return Tool{
		Name:        name,
		Description: name,
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		Read: func(_ context.Context, _ map[string]interface{}) (interface{}, *ChainObservation, error) {
			panic("kaboom")
		},
	}
}

// TestPerCallTimeoutDoesNotWedgeServer is the HIGH-3 test: a hung tool must not wedge the
// stdio loop. With a tiny call budget, a tools/call that blocks returns a timeout (isError)
// AND the server still answers the NEXT request on the same stream.
func TestPerCallTimeoutDoesNotWedgeServer(t *testing.T) {
	srv, err := NewServer(fakeSurface{tools: []Tool{blockingTool("blocks"), okTool("quick")}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.callTimeout = 100 * time.Millisecond // shrink so the test is fast (white-box)

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"blocks","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"quick","arguments":{}}}`,
	}, "\n") + "\n"

	start := time.Now()
	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	elapsed := time.Since(start)

	resps := decodeLines(t, out.String())
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d:\n%s", len(resps), out.String())
	}

	// 1) The blocked call returns a tool error (isError=true) mentioning a deadline.
	r1 := resps[0]["result"].(map[string]interface{})
	if r1["isError"] != true {
		t.Fatalf("blocked call should be isError, got: %v", resps[0])
	}
	txt := r1["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(strings.ToLower(txt), "deadline") && !strings.Contains(strings.ToLower(txt), "context") {
		t.Fatalf("blocked call error %q does not look like a timeout", txt)
	}

	// 2) The SECOND request was answered — the server is still responsive.
	r2 := resps[1]["result"].(map[string]interface{})
	if _, ok := r2["content"]; !ok {
		t.Fatalf("second request not answered (server wedged?): %v", resps[1])
	}

	// Sanity: total time is bounded by the budget, not infinite.
	if elapsed > 5*time.Second {
		t.Fatalf("Serve took %v — the timeout did not bound the hung call", elapsed)
	}
	t.Logf("hung call bounded by per-call timeout; server stayed responsive (elapsed %v)", elapsed)
}

// TestDispatchRecoversPanic is the LOW test: a handler panic becomes one isError tool
// result, not a whole-server crash.
func TestDispatchRecoversPanic(t *testing.T) {
	srv, err := NewServer(fakeSurface{tools: []Tool{panicTool("boom"), okTool("fine")}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	_, err = srv.CallTool(context.Background(), "boom", nil)
	if err == nil {
		t.Fatal("expected a recovered-panic error, got nil")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("error %q is not the recovered-panic error", err.Error())
	}
	// And the server is still usable afterwards.
	if _, err := srv.CallTool(context.Background(), "fine", nil); err != nil {
		t.Fatalf("server unusable after recovered panic: %v", err)
	}
}

// TestOversizedLineIsRejectedAndLoopSurvives is the HIGH-2 test: a request line larger than
// maxLineBytes must be rejected as a parse error WITHOUT buffering it whole, and the stdio
// loop must survive to answer the next (well-formed) request.
func TestOversizedLineIsRejectedAndLoopSurvives(t *testing.T) {
	srv, err := NewServer(fakeSurface{tools: []Tool{okTool("quick")}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// One oversized line (a JSON string padded past the cap) then a valid call.
	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quick","arguments":{"pad":"` +
		strings.Repeat("A", maxLineBytes+1024) + `"}}}`
	valid := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"quick","arguments":{}}}`
	in := huge + "\n" + valid + "\n"

	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	resps := decodeLines(t, out.String())
	if len(resps) != 2 {
		t.Fatalf("want 2 responses (oversized parse error + valid result), got %d", len(resps))
	}
	// 1) Oversized line -> a JSON-RPC parse error (id null since we never parsed it).
	if resps[0]["error"] == nil {
		t.Fatalf("oversized line should yield a parse error, got: %v", resps[0])
	}
	em := resps[0]["error"].(map[string]interface{})
	if int(em["code"].(float64)) != codeParseError {
		t.Fatalf("oversized line error code=%v, want %d", em["code"], codeParseError)
	}
	// 2) The following valid request was still served.
	if _, ok := resps[1]["result"]; !ok {
		t.Fatalf("loop did not survive the oversized line: %v", resps[1])
	}
	t.Logf("oversized line rejected as parse error; loop survived and served the next request")
}

// TestReadLimitedLineDrainsAndResyncs unit-tests the bounded reader directly: an oversized
// line is reported tooLong with no buffered bytes, and the NEXT ReadByte starts on the
// following line (the reader drained to the newline).
func TestReadLimitedLineDrainsAndResyncs(t *testing.T) {
	const max = 16
	data := strings.Repeat("X", max*4) + "\n" + "ok\n"
	r := bufio.NewReader(strings.NewReader(data))

	line, tooLong, err := readLimitedLine(r, max)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !tooLong {
		t.Fatal("expected tooLong=true for the long line")
	}
	if len(line) != 0 {
		t.Fatalf("oversized line should return no buffered bytes, got %d", len(line))
	}
	// Next read returns the SECOND line intact.
	line2, tooLong2, err := readLimitedLine(r, max)
	if err != nil {
		t.Fatalf("unexpected err on line 2: %v", err)
	}
	if tooLong2 {
		t.Fatal("second line is short; tooLong must be false")
	}
	if strings.TrimSpace(string(line2)) != "ok" {
		t.Fatalf("after draining, next line=%q, want %q", strings.TrimSpace(string(line2)), "ok")
	}
}

// TestDuplicateToolNameRejected proves the transport refuses two surfaces (or one surface)
// that declare the same tool name — the index must be unambiguous.
func TestDuplicateToolNameRejected(t *testing.T) {
	a := fakeSurface{tools: []Tool{okTool("dup")}}
	b := fakeSurface{tools: []Tool{okTool("dup")}}
	if _, err := NewServer(a, b); err == nil {
		t.Fatal("expected a duplicate-tool-name error across surfaces, got nil")
	}
}

func TestEmptyToolNameRejected(t *testing.T) {
	for _, name := range []string{"", "   ", "\t"} {
		if _, err := NewServer(fakeSurface{tools: []Tool{okTool(name)}}); err == nil {
			t.Fatalf("expected an empty-tool-name error for %q, got nil", name)
		}
	}
}

func TestNilReadHandlerRejected(t *testing.T) {
	bad := Tool{Name: "noread", Description: "noread", InputSchema: map[string]interface{}{"type": "object"}}
	if _, err := NewServer(fakeSurface{tools: []Tool{bad}}); err == nil {
		t.Fatal("expected a nil-Read-handler error, got nil")
	}
}

// decodeLines parses newline-delimited JSON-RPC responses.
func decodeLines(t *testing.T, s string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	r := bufio.NewReader(strings.NewReader(s))
	for {
		line, err := r.ReadString('\n')
		if tl := strings.TrimSpace(line); tl != "" {
			var m map[string]interface{}
			if jerr := json.Unmarshal([]byte(tl), &m); jerr != nil {
				t.Fatalf("bad response line: %s", tl)
			}
			out = append(out, m)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read line: %v", err)
		}
	}
	return out
}
