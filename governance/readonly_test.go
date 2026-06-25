// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestMCPReadOnlyToolsCannotSubmitTx is the read-only acceptance gate. It proves two
// things:
//
//  1. The package's OWN code (non-test .go files) REFERENCES no transaction-signing
//     or transaction-submitting symbol. The check parses each file with go/parser and
//     inspects the AST — selector expressions (pkg.Symbol), identifiers, and imports —
//     so prose in comments/strings that merely NAMES these tokens (as this package's
//     docs do, to explain the invariant) is correctly ignored. Only real code use
//     fails the test.
//  2. tools/list exposes EXACTLY the eight read tools — no more.
//
// The scan is scoped to non-test files because the test harness legitimately signs
// and sends transactions to set up chain state; the invariant is about the LIBRARY
// the operator runs, not the test scaffolding.
func TestMCPReadOnlyToolsCannotSubmitTx(t *testing.T) {
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
	// CONTEXT-forbidden: a method/func named like a signing op (e.g. "Sign",
	// "GenerateKey") is forbidden ONLY when qualified by a crypto/tx package. This
	// avoids false positives on legitimate, unrelated methods such as
	// (*big.Int).Sign(), which reports a number's sign and is read-only.
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
	// Forbidden imports — packages that exist to sign or send txs.
	forbiddenImports := map[string]bool{
		"github.com/luxfi/geth/accounts/abi/bind": true, // transactors / DeployContract
		"github.com/luxfi/geth/crypto":            true, // signing primitives
		"github.com/luxfi/geth/rpc":               true, // rpc.Client.CallContext can send raw tx
		"reflect":                                 true, // reflect.MethodByName could call a write method past the static denylist
	}
	// Forbidden RPC method strings — even passed as a literal to a generic RPC caller,
	// these are write methods; a read-only server must never name them.
	forbiddenRPCStrings := map[string]bool{
		"eth_sendTransaction":    true,
		"eth_sendRawTransaction": true,
	}
	// Substring markers: any literal CONTAINING one of these is a write-path smell,
	// which defeats string-concatenation evasion ("eth_send"+"RawTransaction") and the
	// bare method verbs ("SendTransaction") that reflect.MethodByName would consume.
	forbiddenRPCStringFragments := map[string]bool{
		"eth_send":           true,
		"SendTransaction":    true,
		"SendRawTransaction": true,
	}

	fset := token.NewFileSet()
	// Walk the WHOLE package tree (this dir AND subpackages such as cmd/aivm-gov-mcp),
	// so a write path added in the command binary cannot slip past a top-dir-only scan.
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
		t.Fatalf("walk package tree: %v", err)
	}

	scanned := 0
	sawCmd := false
	for _, path := range files {
		if sp := filepath.ToSlash(path); strings.Contains(sp, "cmd/") {
			sawCmd = true
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		// Parse WITHOUT comments so prose can never trip the check; we walk the AST,
		// which contains only real code nodes (plus string literals, checked explicitly).
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scanned++

		// Imports.
		for _, imp := range f.Imports {
			ip := strings.Trim(imp.Path.Value, `"`)
			// observation.go imports github.com/luxfi/crypto ONLY for Keccak256 (a pure
			// hash, not signing). That import path is NOT in forbiddenImports, so it is
			// allowed; we additionally assert below that the only crypto symbol it uses
			// is the hash.
			if forbiddenImports[ip] {
				t.Errorf("FORBIDDEN import %q in %s (a signing/tx-send package)", ip, path)
			}
		}

		// Selector, identifier, and string-literal references in real code.
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if alwaysForbidden[x.Sel.Name] {
					t.Errorf("FORBIDDEN write-path symbol %q referenced in %s — the MCP package must be read-only",
						selString(x), path)
				}
				// A signing-named method is forbidden only under a crypto/tx package.
				if signingNames[x.Sel.Name] {
					if pkg, ok := x.X.(*ast.Ident); ok && signingPkgs[pkg.Name] {
						t.Errorf("FORBIDDEN signing call %q in %s — the MCP package must not sign",
							selString(x), path)
					}
				}
			case *ast.Ident:
				// Bare identifiers (e.g. a local named PrivateKey). Only the
				// always-forbidden names are checked bare; signing-named methods are
				// only meaningful when package-qualified (handled above).
				if alwaysForbidden[x.Name] {
					t.Errorf("FORBIDDEN write-path identifier %q in %s", x.Name, path)
				}
			case *ast.BasicLit:
				// Belt-and-suspenders: catch a write JSON-RPC method name passed as a
				// string literal to any generic caller, even if the caller package were
				// allowed. The package legitimately uses no raw RPC method strings.
				// Substring (not exact) match so a FRAGMENTED literal — e.g.
				// "eth_send" + "RawTransaction" — is still caught on each fragment.
				if x.Kind == token.STRING {
					if lit, lerr := unquote(x.Value); lerr == nil {
						if forbiddenRPCStrings[lit] {
							t.Errorf("FORBIDDEN write RPC method string %q in %s — read-only server must not name it", lit, path)
						}
						for marker := range forbiddenRPCStringFragments {
							if strings.Contains(lit, marker) {
								t.Errorf("FORBIDDEN write-path string fragment %q (in %q) in %s — read-only server must not name it", marker, lit, path)
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
		t.Fatal("scan never visited the cmd/ subpackage — the recursive walk is broken (a write path could hide there)")
	}
	t.Logf("AST-scanned %d non-test source files (incl. cmd/): no write-path symbol referenced", scanned)

	// POSITIVE assertion: the ONLY chain dependency is EthCaller, and its method set is
	// EXACTLY the four read methods — no Send*/sign verb. This is stronger than the
	// denylist: a new write method on the chain interface fails here even if its NAME is
	// not on any forbidden list.
	assertEthCallerIsReadOnly(t, fset)

	// tools/list surface: exactly the eight read tools, by name.
	keys := genKeys(t, 1)
	_, env := newEVMChain(t, keys)
	srv := env.mcpServer()

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

// assertCryptoHashOnly verifies that the only github.com/luxfi/crypto symbol used in
// `f` is Keccak256 (a pure hash). Any other crypto.* selector (e.g. crypto.Sign)
// fails — proving observation.go's crypto dependency is hashing, never signing.
func assertCryptoHashOnly(t *testing.T, f *ast.File, name string) {
	t.Helper()
	// Find the local name bound to the crypto import (usually "crypto").
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

// assertEthCallerIsReadOnly parses abi.go, finds the EthCaller interface, and asserts
// its method set is EXACTLY the four read methods. This is the positive complement to
// the denylist: it FAILS if any method is added or renamed (e.g. a SendTransaction
// slipped onto the chain seam), so the read-only surface cannot silently grow. The four
// methods — CallContract (read-only eth_call), ChainID, BlockNumber, HeaderByNumber —
// are all read verbs with no transaction-submitting capability.
func assertEthCallerIsReadOnly(t *testing.T, fset *token.FileSet) {
	t.Helper()
	src, err := os.ReadFile("abi.go")
	if err != nil {
		t.Fatalf("read abi.go: %v", err)
	}
	f, err := parser.ParseFile(fset, "abi.go", src, 0)
	if err != nil {
		t.Fatalf("parse abi.go: %v", err)
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
		if !ok || ts.Name.Name != "EthCaller" {
			return true
		}
		iface, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatalf("EthCaller is not an interface type")
		}
		found = true
		for _, m := range iface.Methods.List {
			// Embedded interfaces (no Names) would widen the surface invisibly — reject.
			if len(m.Names) == 0 {
				t.Errorf("EthCaller embeds another interface — read-only surface must be explicit, not embedded")
				continue
			}
			for _, nm := range m.Names {
				methods = append(methods, nm.Name)
			}
		}
		return false
	})
	if !found {
		t.Fatal("EthCaller interface not found in abi.go — the read-only chain seam is the invariant's anchor")
	}

	sort.Strings(methods)
	got := map[string]bool{}
	for _, m := range methods {
		got[m] = true
		if !want[m] {
			t.Errorf("EthCaller exposes unexpected method %q — only read methods are allowed on the chain seam", m)
		}
	}
	for m := range want {
		if !got[m] {
			t.Errorf("EthCaller is missing expected read method %q", m)
		}
	}
	t.Logf("EthCaller method set verified read-only: %v", methods)
}
