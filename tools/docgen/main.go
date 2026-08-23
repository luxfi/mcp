// Copyright (C) 2022-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// docgen renders the MCP tool reference from the live tool registry (the same
// descriptors tools/list returns), one MDX page per surface, for
// docs.lux.network. Read-only: the surface is built with a non-dialing caller,
// so no chain or network is touched.
//
//	go run ./tools/docgen <out-dir>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/mcp"
	"github.com/luxfi/mcp/evmread"
	"github.com/luxfi/mcp/governance"
)

// noopCaller satisfies the read seam without dialing; Tools() never calls it.
type noopCaller struct{}

func (noopCaller) CallContract(context.Context, gethereum.CallMsg, *big.Int) ([]byte, error) {
	return nil, nil
}
func (noopCaller) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (noopCaller) BlockNumber(context.Context) (uint64, error) { return 0, nil }
func (noopCaller) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return nil, nil
}

var _ evmread.Caller = noopCaller{}

func main() {
	out := "mcp-docs"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		fail(err)
	}
	d := common.HexToAddress("0x0000000000000000000000000000000000000001")
	surf, err := governance.NewWithCaller(noopCaller{}, governance.Config{
		AIParams:          d, AIGovernor: d, AIThoughtRegistry: d, AIReputation: d,
	})
	if err != nil {
		fail(err)
	}
	writeSurface(out, "governance", "Governance read tools — on-chain DAO/AI-governance state, read-only.", surf.Tools())
	os.WriteFile(filepath.Join(out, "meta.json"), []byte(`{"pages":["index","governance"]}`+"\n"), 0o644)
	writeIndex(out)
	fmt.Println("mcp docgen: wrote surface reference to", out)
}

func writeSurface(dir, name, blurb string, tools []mcp.Tool) {
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntitle: %s\ndescription: %s\n---\n\n", name, inline(blurb))
	b.WriteString("{/* Generated from the MCP tool registry by tools/docgen — edit the tool, not this file. */}\n\n")
	fmt.Fprintf(&b, "%s\n\n", prose(blurb))
	for _, t := range tools {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", t.Name, prose(t.Description))
		if len(t.InputSchema) > 0 {
			js, _ := json.MarshalIndent(t.InputSchema, "", "  ")
			fmt.Fprintf(&b, "**Input:**\n\n```json\n%s\n```\n\n", js)
		} else {
			b.WriteString("_No input arguments._\n\n")
		}
	}
	os.WriteFile(filepath.Join(dir, name+".mdx"), []byte(b.String()), 0o644)
}

func writeIndex(dir string) {
	s := "---\ntitle: MCP\ndescription: Read-only Model Context Protocol tools for the Lux chain.\nindex: true\nicon: Plug\n---\n\n" +
		"The Lux MCP server exposes read-only chain state to agents over the Model\n" +
		"Context Protocol. Every tool below is generated from the server's own\n" +
		"registry — the same descriptors `tools/list` returns — so the reference can\n" +
		"never drift from the surface an agent actually sees.\n"
	os.WriteFile(filepath.Join(dir, "index.mdx"), []byte(s), 0o644)
}

func prose(s string) string {
	lines := strings.Split(s, "\n")
	fenced := false
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		ln = strings.ReplaceAll(ln, "<", "&lt;")
		lines[i] = strings.ReplaceAll(ln, "{", "&#123;")
	}
	return strings.Join(lines, "\n")
}

func inline(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), `"`, `'`)
	return strings.ReplaceAll(s, "<", "&lt;")
}

func fail(err error) { fmt.Fprintln(os.Stderr, "mcp docgen:", err); os.Exit(1) }
