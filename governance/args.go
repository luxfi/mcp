// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package governance

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/common/hexutil"
)

// Boundary validation (Hickey: validate at the edge, trust internal functions).
// MCP tool arguments arrive as decoded JSON (numbers are float64, everything else a
// string), so every public-input field is parsed and checked here before any read.

// maxArgStringLen bounds any string-shaped argument (knob keys, 0x-hex ids, decimal/hex
// integers) BEFORE it is parsed, so a multi-megabyte hex/decimal blob is rejected at the
// boundary rather than driving a giant big.Int.SetString or hex decode. Real knob keys,
// 32-byte hashes, addresses and task ids are all well under this.
const maxArgStringLen = 4096

// argString returns a required string argument, rejecting absurdly long inputs.
func argString(args map[string]interface{}, name string) (string, error) {
	v, ok := args[name]
	if !ok {
		return "", fmt.Errorf("%s: missing required argument %q", "args", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("args: %q must be a string", name)
	}
	if len(s) > maxArgStringLen {
		return "", fmt.Errorf("args: %q is too long (%d > %d bytes)", name, len(s), maxArgStringLen)
	}
	return s, nil
}

// argBytes32 parses a required 0x-hex bytes32 argument.
func argBytes32(args map[string]interface{}, name string) ([32]byte, error) {
	var out [32]byte
	s, err := argString(args, name)
	if err != nil {
		return out, err
	}
	b, err := hexutil.Decode(ensure0x(s))
	if err != nil {
		return out, fmt.Errorf("args: %q is not valid hex: %w", name, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("args: %q must be 32 bytes, got %d", name, len(b))
	}
	copy(out[:], b)
	return out, nil
}

// argAddress parses a required 0x-hex address argument.
func argAddress(args map[string]interface{}, name string) (common.Address, error) {
	s, err := argString(args, name)
	if err != nil {
		return common.Address{}, err
	}
	s = ensure0x(s)
	if !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("args: %q is not a valid address", name)
	}
	return common.HexToAddress(s), nil
}

// argUint256 parses a required unsigned integer (used for task/round ids). Accepts a
// JSON number, a decimal string, or a 0x-hex string. Negative values are rejected.
func argUint256(args map[string]interface{}, name string) (*big.Int, error) {
	v, ok := args[name]
	if !ok {
		return nil, fmt.Errorf("args: missing required argument %q", name)
	}
	n, err := toBigInt(v)
	if err != nil {
		return nil, fmt.Errorf("args: %q: %w", name, err)
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("args: %q must be non-negative", name)
	}
	return n, nil
}

// maxLimit is the hard cap on any "limit" argument. It bounds the per-tool read fan-out
// (param_history issues ~2 eth_calls per round, so maxLimit rounds stays well under the
// per-request eth_call ceiling in server.go). MCP results are small; a caller never
// legitimately needs more in one call.
const maxLimit = 256

// argLimit reads an optional positive "limit" argument, falling back to def. A
// non-positive or absent limit yields def; anything over maxLimit is clamped to maxLimit
// so a caller cannot force an unbounded scan.
func argLimit(args map[string]interface{}, def int) int {
	v, ok := args["limit"]
	if !ok {
		return def
	}
	n, err := toBigInt(v)
	if err != nil || n.Sign() <= 0 {
		return def
	}
	if !n.IsInt64() || n.Int64() > maxLimit {
		return maxLimit
	}
	return int(n.Int64())
}

// argFromRound reads the optional "fromRound" argument; nil (use default) when
// absent or unparseable. Clamped to <= count-1 by the caller.
func argFromRound(args map[string]interface{}, count *big.Int) *big.Int {
	v, ok := args["fromRound"]
	if !ok {
		return nil
	}
	n, err := toBigInt(v)
	if err != nil || n.Sign() < 0 {
		return nil
	}
	return n
}

// toBigInt converts a decoded-JSON value (float64, json.Number, or string) to a
// *big.Int. Floats must be integral. Strings may be decimal or 0x-hex.
func toBigInt(v interface{}) (*big.Int, error) {
	switch t := v.(type) {
	case float64:
		if t != float64(int64(t)) {
			return nil, fmt.Errorf("expected an integer, got %v", t)
		}
		return big.NewInt(int64(t)), nil
	case json.Number:
		n, ok := new(big.Int).SetString(t.String(), 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", t.String())
		}
		return n, nil
	case string:
		// Bound the raw string BEFORE parsing so a multi-MB numeric literal cannot drive
		// an unbounded big.Int allocation.
		if len(t) > maxArgStringLen {
			return nil, fmt.Errorf("integer string too long (%d > %d bytes)", len(t), maxArgStringLen)
		}
		s := strings.TrimSpace(t)
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			n, ok := new(big.Int).SetString(s[2:], 16)
			if !ok {
				return nil, fmt.Errorf("invalid hex integer %q", s)
			}
			return n, nil
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", s)
		}
		return n, nil
	default:
		return nil, fmt.Errorf("expected a number, got %T", v)
	}
}

func ensure0x(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s
	}
	return "0x" + s
}

// ----------------------------------------------------------------------------
// JSON-schema helpers for the tool descriptors (tools/list inputSchema).
// ----------------------------------------------------------------------------

func objSchema(props map[string]interface{}, required []string) map[string]interface{} {
	if props == nil {
		props = map[string]interface{}{}
	}
	schema := map[string]interface{}{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func strSchema(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "string", "description": desc}
}

func intSchema(desc string) map[string]interface{} {
	return map[string]interface{}{"type": "integer", "description": desc}
}
