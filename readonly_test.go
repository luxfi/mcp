// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mcp_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	gethereum "github.com/luxfi/geth"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"

	"github.com/luxfi/mcp"
	"github.com/luxfi/mcp/evmread"
	"github.com/luxfi/mcp/governance"
)

// TestModuleIsReadOnly is the read-only acceptance gate for the WHOLE shared module
// (root mcp + evmread + governance + cmd). It proves five things:
//
//  1. The module's non-test code REFERENCES no transaction-signing or transaction-
//     submitting symbol (AST scan — prose in comments/strings is ignored).
//  2. The ROOT go-ethereum package (github.com/luxfi/geth) is imported by exactly ONE
//     package: the evmread adapter. Nothing else may import it.
//  3. NO package imports accounts/abi/bind, geth/crypto, geth/rpc, or reflect.
//  4. evmread.Caller's method set is EXACTLY the four read verbs — a positive assertion
//     stronger than the denylist (a new write method fails here even if unnamed on a list).
//  5. tools/list exposes EXACTLY the eight governance read tools — no more.
//
// The scan is scoped to non-test files because the test harness legitimately signs and
// sends transactions to set up chain state; the invariant is about the LIBRARY the
// operator runs, not the test scaffolding.
func TestModuleIsReadOnly(t *testing.T) {
	// ALWAYS-forbidden symbols — these names have no legitimate read-only use, so any
	// reference (qualified or bare) is a failure.
	alwaysForbidden := map[string]bool{
		"SendTransaction":               true, // ethclient / bind send a tx
		"sendRawTransaction":            true, // raw JSON-RPC tx submit
		"SendRawTransaction":            true,
		"NewKeyedTransactor":            true, // keyed transactor (signing)
		"NewKeyedTransactorWithChainID": true,
		"DeployContract":                true, // sends a creation tx
		"PrivateKey":                    true, // ecdsa.PrivateKey / *.PrivateKey field
	}
	// CONTEXT-forbidden: a method/func named like a signing op (e.g. "Sign", "GenerateKey")
	// is forbidden ONLY when qualified by a crypto/tx package. This avoids false positives on
	// legitimate, unrelated methods such as (*big.Int).Sign(), which reports a number's sign
	// and is read-only.
	signingNames := map[string]bool{
		"Sign":        true,
		"SignTx":      true,
		"SignText":    true,
		"SignHash":    true,
		"GenerateKey": true,
	}
	signingPkgs := map[string]bool{
		"crypto": true, // luxfi/crypto or geth/crypto signing
		"ecdsa":  true, // crypto/ecdsa
		"bind":   true, // accounts/abi/bind
		"types":  true, // types.SignTx
	}
	// Forbidden imports — packages that exist to sign or send txs (plus reflect, which could
	// call a write method past the static denylist).
	forbiddenImports := map[string]bool{
		"github.com/luxfi/geth/accounts/abi/bind": true, // transactors / DeployContract
		"github.com/luxfi/geth/crypto":            true, // signing primitives
		"github.com/luxfi/geth/rpc":               true, // rpc.Client.CallContext can send raw tx
		"reflect":                                 true, // reflect.MethodByName could call a write method past the static denylist
	}
	// Forbidden RPC method strings — even passed as a literal to a generic RPC caller, these
	// are write methods; a read-only server must never name them.
	forbiddenRPCStrings := map[string]bool{
		"eth_sendTransaction":    true,
		"eth_sendRawTransaction": true,
	}
	// Substring markers: any literal CONTAINING one of these is a write-path smell, which
	// defeats string-concatenation evasion ("eth_send"+"RawTransaction") and the bare method
	// verbs ("SendTransaction") that reflect.MethodByName would consume.
	forbiddenRPCStringFragments := map[string]bool{
		"eth_send":           true,
		"SendTransaction":    true,
		"SendRawTransaction": true,
	}

	fset := token.NewFileSet()
	// Walk the WHOLE module tree from the module root (this package's dir): root mcp +
	// evmread + governance + cmd. A write path added anywhere cannot slip past a single-dir
	// scan.
	var files []string
	if err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip testdata (compiled-contract JSON, not Go) — nothing to parse there.
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		t.Fatalf("walk module tree: %v", err)
	}

	scanned := 0
	sawCmd := false
	sawEvmread := false
	sawGovernance := false
	gethImporters := map[string]bool{} // package dir -> imports root geth
	for _, path := range files {
		sp := filepath.ToSlash(path)
		if strings.Contains(sp, "cmd/") {
			sawCmd = true
		}
		if strings.Contains(sp, "evmread/") {
			sawEvmread = true
		}
		if strings.Contains(sp, "governance/") {
			sawGovernance = true
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Parse WITHOUT comments so prose can never trip the check; we walk the AST, which
		// contains only real code nodes (plus string literals, checked explicitly).
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scanned++

		pkgDir := filepath.Dir(sp)

		// Imports.
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			// observation.go imports github.com/luxfi/crypto ONLY for Keccak256 (a pure hash,
			// not signing). That import path is NOT in forbiddenImports, so it is allowed; we
			// additionally assert below that the only crypto symbol it uses is the hash.
			if forbiddenImports[ip] {
				t.Errorf("FORBIDDEN import %q in %s (a signing/tx-send package)", ip, path)
			}
			// The ONE allowed importer of the ROOT go-ethereum package is evmread.
			if ip == "github.com/luxfi/geth" {
				gethImporters[pkgDir] = true
			}
		}

		// Selector, identifier, and string-literal references in real code.
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if alwaysForbidden[x.Sel.Name] {
					t.Errorf("FORBIDDEN write-path symbol %q referenced in %s — the module must be read-only",
						selString(x), path)
				}
				// A signing-named method is forbidden only under a crypto/tx package.
				if signingNames[x.Sel.Name] {
					if pkg, ok := x.X.(*ast.Ident); ok && signingPkgs[pkg.Name] {
						t.Errorf("FORBIDDEN signing call %q in %s — the module must not sign",
							selString(x), path)
					}
				}
			case *ast.Ident:
				// Bare identifiers (e.g. a local named PrivateKey). Only the always-forbidden
				// names are checked bare; signing-named methods are only meaningful when
				// package-qualified (handled above).
				if alwaysForbidden[x.Name] {
					t.Errorf("FORBIDDEN write-path identifier %q in %s", x.Name, path)
				}
			case *ast.BasicLit:
				// Belt-and-suspenders: catch a write JSON-RPC method name passed as a string
				// literal to any generic caller, even if the caller package were allowed. The
				// module legitimately uses no raw RPC method strings. Substring (not exact)
				// match so a FRAGMENTED literal — e.g. "eth_send" + "RawTransaction" — is still
				// caught on each fragment.
				if x.Kind == token.STRING {
					if lit, lerr := unquote(x.Value); lerr == nil {
						if forbiddenRPCStrings[lit] {
							t.Errorf("FORBIDDEN write RPC method string %q in %s — read-only module must not name it", lit, path)
						}
						for marker := range forbiddenRPCStringFragments {
							if strings.Contains(lit, marker) {
								t.Errorf("FORBIDDEN write-path string fragment %q (in %q) in %s — read-only module must not name it", marker, lit, path)
							}
						}
					}
				}
			}
			return true
		})

		// The one allowed crypto use (observation.go) must be Keccak256 ONLY.
		if filepath.Base(path) == "observation.go" {
			assertCryptoHashOnly(t, f, path)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 source files — scan is broken")
	}
	if !sawCmd {
		t.Fatal("scan never visited cmd/ — the recursive walk is broken (a write path could hide there)")
	}
	if !sawEvmread {
		t.Fatal("scan never visited evmread/ — the recursive walk is broken")
	}
	if !sawGovernance {
		t.Fatal("scan never visited governance/ — the recursive walk is broken")
	}
	t.Logf("AST-scanned %d non-test source files (root + evmread + governance + cmd): no write-path symbol referenced", scanned)

	// The ROOT go-ethereum package must be imported by EXACTLY the evmread adapter.
	if len(gethImporters) != 1 || !gethImporters["evmread"] {
		t.Errorf("root github.com/luxfi/geth must be imported ONLY by evmread; importers=%v", keysOf(gethImporters))
	} else {
		t.Logf("root github.com/luxfi/geth imported ONLY by evmread (the sole adapter): %v", keysOf(gethImporters))
	}

	// POSITIVE assertion: the ONLY chain dependency is evmread.Caller, and its method set is
	// EXACTLY the four read methods — no Send*/sign verb.
	assertCallerIsReadOnly(t, fset)

	// tools/list surface: exactly the eight read tools, by name. Tools() returns the static
	// descriptors regardless of the caller, so a non-dialing fake caller suffices here.
	addr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	g, err := governance.NewWithCaller(noopCaller{}, governance.Config{
		AIParams:          addr,
		AIGovernor:        addr,
		AIThoughtRegistry: addr,
		AIReputation:      addr,
	})
	if err != nil {
		t.Fatalf("build governance surface: %v", err)
	}
	srv, err := mcp.NewServer(g)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}

	got := make([]string, 0, len(srv.Tools()))
	for _, tl := range srv.Tools() {
		got = append(got, tl.Name)
	}
	sort.Strings(got)

	want := []string{
		"chain_state",
		"operator_reputation",
		"param_history",
		"param_value",
		"pending_operations",
		"quorum_status",
		"receipt_lookup",
		"thought_status",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("tools/list returned %d tools, want exactly 8: %v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tool[%d] = %q, want %q (full set: %v)", i, got[i], want[i], got)
		}
	}
}

// assertCryptoHashOnly verifies that the only github.com/luxfi/crypto symbol used in `f`
// is Keccak256 (a pure hash). Any other crypto.* selector (e.g. crypto.Sign) fails —
// proving observation.go's crypto dependency is hashing, never signing.
func assertCryptoHashOnly(t *testing.T, f *ast.File, name string) {
	t.Helper()
	alias := ""
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "github.com/luxfi/crypto" {
			if imp.Name != nil {
				alias = imp.Name.Name
			} else {
				alias = "crypto"
			}
		}
	}
	if alias == "" {
		return // crypto not imported here
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != alias {
			return true
		}
		if sel.Sel.Name != "Keccak256" && sel.Sel.Name != "Keccak256Hash" {
			t.Errorf("%s uses crypto.%s — only the keccak hash is permitted (no signing)", name, sel.Sel.Name)
		}
		return true
	})
}

// assertCallerIsReadOnly parses the evmread adapter, finds the Caller interface, and
// asserts its method set is EXACTLY the four read methods. FAILS if any method is added or
// renamed (e.g. a SendTransaction slipped onto the chain seam), so the read-only surface
// cannot silently grow. The four methods — CallContract (read-only eth_call), ChainID,
// BlockNumber, HeaderByNumber — are all read verbs with no transaction-submitting
// capability.
func assertCallerIsReadOnly(t *testing.T, fset *token.FileSet) {
	t.Helper()
	const path = "evmread/evmread.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	want := map[string]bool{
		"CallContract":   true,
		"ChainID":        true,
		"BlockNumber":    true,
		"HeaderByNumber": true,
	}

	var methods []string
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Caller" {
			return true
		}
		iface, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatalf("Caller is not an interface type")
		}
		found = true
		for _, m := range iface.Methods.List {
			// Embedded interfaces (no Names) would widen the surface invisibly — reject.
			if len(m.Names) == 0 {
				t.Errorf("evmread.Caller embeds another interface — read-only surface must be explicit, not embedded")
				continue
			}
			for _, nm := range m.Names {
				methods = append(methods, nm.Name)
			}
		}
		return false
	})
	if !found {
		t.Fatal("evmread.Caller interface not found — the read-only chain seam is the invariant's anchor")
	}

	sort.Strings(methods)
	got := map[string]bool{}
	for _, m := range methods {
		got[m] = true
		if !want[m] {
			t.Errorf("evmread.Caller exposes unexpected method %q — only read methods are allowed on the chain seam", m)
		}
	}
	for m := range want {
		if !got[m] {
			t.Errorf("evmread.Caller is missing expected read method %q", m)
		}
	}
	t.Logf("evmread.Caller method set verified read-only: %v", methods)
}

// selString renders a selector expression like "pkg.Symbol" for error messages.
func selString(s *ast.SelectorExpr) string {
	if id, ok := s.X.(*ast.Ident); ok {
		return id.Name + "." + s.Sel.Name
	}
	return s.Sel.Name
}

// unquote strips Go string-literal quoting (handles both "..." and `...`).
func unquote(lit string) (string, error) {
	return strconv.Unquote(lit)
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noopCaller is a non-dialing evmread.Caller for the tools/list assertion (Tools() never
// touches the chain, so these methods are never called). It exists only to satisfy the
// read-only seam without a network dial.
type noopCaller struct{}

func (noopCaller) CallContract(_ context.Context, _ gethereum.CallMsg, _ *big.Int) ([]byte, error) {
	return nil, nil
}
func (noopCaller) ChainID(context.Context) (*big.Int, error)   { return big.NewInt(1), nil }
func (noopCaller) BlockNumber(context.Context) (uint64, error) { return 0, nil }
func (noopCaller) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return nil, nil
}

var _ evmread.Caller = noopCaller{}
