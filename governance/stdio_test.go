// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/luxfi/mcp"
)

// TestStdioServeRoundTrip exercises the ACTUAL JSON-RPC 2.0 stdio loop (Serve),
// not just the in-process CallTool: it feeds initialize, tools/list, and a
// tools/call(chain_state) over a pipe and asserts the framed responses. This proves
// the transport envelope (initialize handshake, tools/list shape, tools/call content
// block) works end-to-end against the real EVM-backed reads.
func TestStdioServeRoundTrip(t *testing.T) {
	keys := genKeys(t, 1)
	_, env := newEVMChain(t, keys)
	srv := env.mcpServer()

	// Three newline-delimited requests + a notification (no id, no response).
	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"chain_state","arguments":{}}}`,
	}, "\n") + "\n"

	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(requests), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	resps := decodeLines(t, out.String())
	// initialize + tools/list + tools/call = 3 responses; the notification yields none.
	if len(resps) != 3 {
		t.Fatalf("expected 3 responses (notification yields none), got %d:\n%s", len(resps), out.String())
	}

	// 1) initialize: serverInfo.name == ServerName, protocolVersion set.
	init := resps[0]
	if idNum(init["id"]) != 1 {
		t.Fatalf("initialize response id=%v, want 1", init["id"])
	}
	result := init["result"].(map[string]interface{})
	si := result["serverInfo"].(map[string]interface{})
	if si["name"] != mcp.ServerName {
		t.Fatalf("serverInfo.name=%v, want %s", si["name"], mcp.ServerName)
	}
	if result["protocolVersion"] != mcp.ProtocolVersion {
		t.Fatalf("protocolVersion=%v, want %s", result["protocolVersion"], mcp.ProtocolVersion)
	}

	// 2) tools/list: exactly 8 tools.
	list := resps[1]["result"].(map[string]interface{})
	tools := list["tools"].([]interface{})
	if len(tools) != 8 {
		t.Fatalf("tools/list returned %d tools, want 8", len(tools))
	}
	// Each tool descriptor must carry name + inputSchema (the MCP shape).
	for _, tl := range tools {
		td := tl.(map[string]interface{})
		if _, ok := td["name"].(string); !ok {
			t.Fatalf("tool descriptor missing name: %v", td)
		}
		if _, ok := td["inputSchema"].(map[string]interface{}); !ok {
			t.Fatalf("tool descriptor missing inputSchema: %v", td)
		}
	}

	// 3) tools/call(chain_state): content[0].text is a JSON object carrying the tool VALUE
	//    plus the verifiable observation. The chain_state fields live under "value"; the
	//    observation under "observation" (the MED-8 wiring — every result is bindable).
	call := resps[2]["result"].(map[string]interface{})
	content := call["content"].([]interface{})
	if len(content) != 1 {
		t.Fatalf("tools/call content length=%d, want 1", len(content))
	}
	block := content[0].(map[string]interface{})
	if block["type"] != "text" {
		t.Fatalf("content type=%v, want text", block["type"])
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(block["text"].(string)), &payload); err != nil {
		t.Fatalf("chain_state text not JSON: %v", err)
	}
	state, ok := payload["value"].(map[string]interface{})
	if !ok {
		t.Fatalf("tool result missing value object: %v", payload)
	}
	wantChainID, _ := env.c.ChainID(context.Background())
	if state["chainId"] != wantChainID.String() {
		t.Fatalf("chain_state chainId=%v, want %s", state["chainId"], wantChainID)
	}
	if _, ok := state["blockHash"].(string); !ok {
		t.Fatalf("chain_state missing blockHash: %v", state)
	}
	if _, ok := state["blockNumber"]; !ok {
		t.Fatalf("chain_state missing blockNumber: %v", state)
	}

	// The observation must be present and carry a binding hash + the tool name.
	obs, ok := payload["observation"].(map[string]interface{})
	if !ok {
		t.Fatalf("tool result missing observation object: %v", payload)
	}
	if obs["tool"] != "chain_state" {
		t.Fatalf("observation tool=%v, want chain_state", obs["tool"])
	}
	if _, ok := obs["hash"].(string); !ok {
		t.Fatalf("observation missing binding hash: %v", obs)
	}
}

// TestStdioUnknownToolIsError verifies an unknown tool returns an MCP tool error
// (isError=true content), not a transport crash.
func TestStdioUnknownToolIsError(t *testing.T) {
	keys := genKeys(t, 1)
	_, env := newEVMChain(t, keys)
	srv := env.mcpServer()

	req := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}` + "\n"
	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(req), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	resps := decodeLines(t, out.String())
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	// An unknown tool is a JSON-RPC method-not-found error (we reject before dispatch).
	if resps[0]["error"] == nil {
		t.Fatalf("expected an error for unknown tool, got: %v", resps[0])
	}
}

// decodeLines parses newline-delimited JSON-RPC responses.
func decodeLines(t *testing.T, s string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	r := bufio.NewReader(strings.NewReader(s))
	for {
		line, err := r.ReadString('\n')
		if t := strings.TrimSpace(line); t != "" {
			var m map[string]interface{}
			if jerr := json.Unmarshal([]byte(t), &m); jerr != nil {
				panic("bad response line: " + t)
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

// idNum extracts a numeric JSON-RPC id (decoded as float64).
func idNum(v interface{}) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return -1
}
