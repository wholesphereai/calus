"""calus.integrations.mcp.guardrail_providers

Plugin package for MCP guardrail providers. `load_guardrail_providers()` walks
this package and registers every class exposing a `name` property and a
`check_server_config` method. Drop a new `*.py` module here to add a provider.
"""
