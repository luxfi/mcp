// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command lux-mcp is the drop-in, READ-ONLY governance MCP server binary for the Lux
// AIVM (A-Chain) governance stack. It reads its EVM RPC URL and the four deployed
// contract addresses from the environment and serves the governance read tools over
// stdio (JSON-RPC 2.0) via the shared mcp transport. It holds no key and submits no
// transaction.
//
// Environment:
//
//	LUX_GOV_EVM_RPC              EVM RPC URL of the governance chain (required)
//	LUX_AIPARAMS_ADDR            AIParams contract address (required)
//	LUX_AIGOVERNOR_ADDR          AIGovernor contract address (required)
//	LUX_AITHOUGHTREGISTRY_ADDR   AIThoughtRegistry contract address (required)
//	LUX_AIREPUTATION_ADDR        AIReputation contract address (required)
//
// Drop into an MCP client (hanzo-dev / claude desktop) as a stdio server:
//
//	{ "command": "lux-mcp", "env": { "LUX_GOV_EVM_RPC": "https://…/ext/bc/C/rpc", … } }
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/mcp"
	"github.com/luxfi/mcp/governance"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lux-mcp:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	surface, err := governance.New(ctx, cfg)
	if err != nil {
		return err
	}
	// One transport, one surface: mcp.Serve runs the read-only stdio loop over the
	// governance tools. Adding another domain is just another argument here.
	return mcp.Serve(ctx, os.Stdin, os.Stdout, surface)
}

func configFromEnv() (governance.Config, error) {
	var cfg governance.Config
	cfg.EVMRPC = os.Getenv("LUX_GOV_EVM_RPC")
	if cfg.EVMRPC == "" {
		return cfg, fmt.Errorf("LUX_GOV_EVM_RPC is required")
	}
	var err error
	if cfg.AIParams, err = envAddr("LUX_AIPARAMS_ADDR"); err != nil {
		return cfg, err
	}
	if cfg.AIGovernor, err = envAddr("LUX_AIGOVERNOR_ADDR"); err != nil {
		return cfg, err
	}
	if cfg.AIThoughtRegistry, err = envAddr("LUX_AITHOUGHTREGISTRY_ADDR"); err != nil {
		return cfg, err
	}
	if cfg.AIReputation, err = envAddr("LUX_AIREPUTATION_ADDR"); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func envAddr(name string) (common.Address, error) {
	v := os.Getenv(name)
	if v == "" {
		return common.Address{}, fmt.Errorf("%s is required", name)
	}
	if !common.IsHexAddress(v) {
		return common.Address{}, fmt.Errorf("%s=%q is not a valid address", name, v)
	}
	return common.HexToAddress(v), nil
}
