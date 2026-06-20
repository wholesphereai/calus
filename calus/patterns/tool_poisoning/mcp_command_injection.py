"""tool-poisoning: mcp-command-injection  (3 patterns)"""

PATTERNS = [
    ('(?i)\\b(?:kubectl_scale|kubectl_patch|explain_resource)\\b[^\\n]{0,80}(?:;|\\|\\||&&|\\||`|\\$\\()[^\\n]{0,60}(?:curl|wget|nc|ncat|bash|sh|python3?|perl|ruby|node|powershell|cmd(?:\\.exe)?|rm|cat|whoami|id|env|export|chmod|kubectl|cp|mv|eval|base64)\\b', 'high', 'An mcp-server-kubernetes kubectl tool name (kubectl_scale / kubectl_patch / explain_resource) followed on the same line by a shell separator'),
    ('(?i)"(?:name|resourceName|resourceType|replicas|patchData|patch)"\\s*:\\s*"[^"\\n]{0,120}(?:;\\s*|\\|\\|?\\s*|&&\\s*|`|\\$\\()[^"\\n]{0,80}(?:curl|wget|nc|bash|sh|python3?|\\brm\\s|\\bcat\\s|whoami|id;|env;|chmod|base64|eval)', 'high', 'JSON tool-call arguments for the kubectl MCP tools where a kubectl_scale/kubectl_patch/explain_resource parameter value embeds a shell separ'),
    ('(?i)\\bexplain_resource\\b[^\\n]{0,40}(?:resourceType|name|arguments)\\s*[:=]\\s*["\'][^"\'\\n]{0,80}(?:`[^`\\n]{1,80}`|\\$\\([^)\\n]{1,80}\\))', 'high', 'An explain_resource MCP tool invocation whose resourceType/name argument contains a backtick or $() command substitution passed straight int'),
]