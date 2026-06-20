"""calus: input_validation  (4 patterns)"""

PATTERNS = [
    ('(?i)def\\s+(?:git_init|git_clone|git_checkout|git_status|git_diff|git_commit).*:\\s*$', 'high', 'mcp-git-no-path-validation: MCP git tool implementation that accepts paths without proper\nvalidation. All path parameters should be validate'),
    ('(?i)(?:git_path|repo_path|clone_path|checkout_path)\\s*=\\s*(?:args|params|input)', 'high', 'mcp-git-no-path-validation: MCP git tool implementation that accepts paths without proper\nvalidation. All path parameters should be validate'),
    ('(?i)git.*(?:branch|tag|remote).*(?:args|params|input)', 'medium', "mcp-git-tool-missing-allowlist: MCP git tool that doesn't restrict which git subcommands can\nbe executed. Implement an allowlist of permitte"),
    ('(?i)git.*(?:push|pull|fetch).*(?:user|request)', 'medium', "mcp-git-tool-missing-allowlist: MCP git tool that doesn't restrict which git subcommands can\nbe executed. Implement an allowlist of permitte"),
]