# Lux MCP

.PHONY: docs
docs: ## Generate the MCP tool reference into docs.lux.network
	GOWORK=off go run ./tools/docgen $(HOME)/work/lux/docs/apps/docs/content/docs/mcp
