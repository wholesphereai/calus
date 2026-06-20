"""calus: cross_server  (5 patterns)"""

PATTERNS = [
    ('(?:registerTool|server\\.tool|\\.tool)\\s*\\([^)]*name\\s*[=:]\\s*["\\\'](?:read|write|execute|shell|file)', 'medium', 'cross-server-attack-common-tool-name-that-could-sh: '),
    ('(listServers|getServers|discoverServers|enumServers)', 'medium', 'cross-server-attack-server-enumeration-function: '),
    ('(connectTo|proxyTo|forwardTo)\\s*\\(\\s*[^)]*\\+', 'high', 'cross-server-attack-dynamic-server-connection: '),
    ('(unregisterServer|removeServer|replaceServer)\\s*\\(', 'high', 'cross-server-attack-server-manipulation: '),
    ('server\\s*\\[\\s*["\\\'].*["\\\']\\s*\\]\\s*=', 'medium', 'cross-server-attack-dynamic-server-assignment: '),
]