// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp_test

import (
	"context"
	"sort"
	"testing"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/mcp"
	"github.com/luxfi/mcp/governance"
)

// pingSurface is a tiny, chain-free Surface contributing ONE tool. It exists to prove the
// transport is domain-agnostic: it composes the real governance Surface with an unrelated
// surface and dispatches to each. (Decomplect proof: the transport knows nothing about any
// domain — a domain is just a []Tool.)
type pingSurface struct{}

func (pingSurface) Tools() []mcp.Tool {
	return []mcp.Tool{{
		Name:        "ping",
		Description: "returns pong",
		InputSchema: map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		Read: func(_ context.Context, _ map[string]interface{}) (interface{}, *mcp.ChainObservation, error) {
			return map[string]interface{}{"pong": true}, nil, nil
		},
	}}
}

// TestTransportComposesMultipleSurfaces proves the ONE transport serves TWO independent
// surfaces at once: tools/list is the UNION of both surfaces' tools, and tools/call
// dispatches to the correct surface. This is the composition guarantee — the transport is
// generic over surfaces, not bound to governance.
func TestTransportComposesMultipleSurfaces(t *testing.T) {
	addr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	// The governance Surface registers its 8 tools regardless of the caller (Tools() and the
	// composition assertions below do not read the chain), so a non-dialing fake caller is
	// enough to construct it here.
	gov, err := governance.NewWithCaller(noopCaller{}, governance.Config{
		AIParams:          addr,
		AIGovernor:        addr,
		AIThoughtRegistry: addr,
		AIReputation:      addr,
	})
	if err != nil {
		t.Fatalf("build governance surface: %v", err)
	}

	srv, err := mcp.NewServer(gov, pingSurface{})
	if err != nil {
		t.Fatalf("compose surfaces: %v", err)
	}

	// tools/list is the union: 8 governance tools + 1 ping = 9, all distinct.
	got := make([]string, 0, len(srv.Tools()))
	for _, tl := range srv.Tools() {
		got = append(got, tl.Name)
	}
	sort.Strings(got)
	want := []string{
		"chain_state", "operator_reputation", "param_history", "param_value",
		"pending_operations", "ping", "quorum_status", "receipt_lookup", "thought_status",
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("composed tools/list has %d tools, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("composed tool[%d]=%q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}

	// Dispatch to the NON-governance surface's tool proves the transport routes by name
	// across surfaces (no chain needed for ping).
	res, err := srv.CallTool(context.Background(), "ping", nil)
	if err != nil {
		t.Fatalf("dispatch ping: %v", err)
	}
	m, ok := res.(map[string]interface{})
	if !ok || m["pong"] != true {
		t.Fatalf("ping result=%v, want {pong:true}", res)
	}

	// Dispatching a governance tool by name also resolves through the SAME transport. We use
	// a tool whose error path is reached without a live chain read returning bad bytes:
	// param_value with a malformed argument fails at argument validation (boundary), proving
	// the governance tool was dispatched (not "unknown tool").
	_, err = srv.CallTool(context.Background(), "param_value", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected param_value to fail on missing args (proving it dispatched), got nil")
	}
	if err.Error() == `mcp: unknown tool "param_value"` {
		t.Fatalf("param_value was not dispatched through the composed transport: %v", err)
	}
}
