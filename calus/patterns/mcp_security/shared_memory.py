"""calus: shared-memory  (18 patterns)"""

PATTERNS = [
    ('(?i)(?:from|import)\\s+shared_memory\\s*(?:,\\s*|$)', 'low', 'shared-memory-poisoning-patterns: Detects code patterns that allow writing to shared memory without integrity checks, enabling memory poison'),
    ('(?i)\\bshared_memory\\b.{0,40}\\.(?:update|write|store)\\(', 'low', 'shared-memory-poisoning-patterns: Detects code patterns that allow writing to shared memory without integrity checks, enabling memory poison'),
    ('(?i)\\bmemory_pool\\s*\\[.{0,40}\\]\\s*=\\s*', 'low', 'shared-memory-poisoning-patterns: Detects code patterns that allow writing to shared memory without integrity checks, enabling memory poison'),
    ('(?i)(?:shared_memory|global_memory|mem_store)\\.(?:read|write|get|set)\\s*\\(', 'low', 'mcp-shared-memory-direct-access: Detects code that directly accesses shared memory without going through an access control layer, as describ'),
    ('(?i)(?:from|import)\\s+.{0,40}shared_memory', 'low', 'mcp-shared-memory-direct-access: Detects code that directly accesses shared memory without going through an access control layer, as describ'),
    ('(?i)memcache\\s*=\\s*.{0,40}(?:shared|global)', 'low', 'mcp-shared-memory-direct-access: Detects code that directly accesses shared memory without going through an access control layer, as describ'),
    ('shared_memory\\.read\\(\\s*[\'"][^\'"]*[\'"]\\s*\\)', 'medium', 'mcp-shared-memory-access-without-isolation: Detects shared memory access without hierarchical isolation layers, as targeted by AgenticCyOps '),
    ('memory_pool\\.get\\(\\s*[\'"][^\'"]*[\'"]\\s*\\)', 'medium', 'mcp-shared-memory-access-without-isolation: Detects shared memory access without hierarchical isolation layers, as targeted by AgenticCyOps '),
    ('(?i)read\\s+shared\\s+memory\\s+(?:without|no)\\s+isolation', 'medium', 'mcp-shared-memory-access-without-isolation: Detects shared memory access without hierarchical isolation layers, as targeted by AgenticCyOps '),
    ('(?i)\\bshared\\s+memory\\b.{0,40}?\\b(?:all|any)\\s+agent\\b', 'low', 'shared-memory-unrestricted-access: Detects code that allows shared memory access without access control, enabling lateral compromise.'),
    ('(?i)\\bmemory\\s+pool\\b.{0,40}?\\b(?:unrestricted|no\\s+auth)\\b', 'low', 'shared-memory-unrestricted-access: Detects code that allows shared memory access without access control, enabling lateral compromise.'),
    ('(?i)\\b(?:shared_memory|global_memory|common_store)\\b.{0,40}\\b(?:read|get|query|retrieve)\\b', 'high', 'mcp-shared-memory-cross-agent-read: Detects code that allows cross-agent read access to shared memory without access control, enabling later'),
    ('(?i)memory\\.(?:get|read|retrieve)\\s*\\(\\s*[^)]*\\b(?:all|shared|global)\\b', 'high', 'mcp-shared-memory-cross-agent-read: Detects code that allows cross-agent read access to shared memory without access control, enabling later'),
    ('(?i)class\\s+\\w*SharedMemory\\w*\\s*[:]', 'medium', 'mcp-shared-memory-unprotected-access: Detects shared memory access without hierarchical isolation or access control, a vulnerability exploit'),
    ('(?i)\\bshared_memory\\b.{0,40}\\b(?:read|write|fetch|store)\\b', 'medium', 'mcp-shared-memory-unprotected-access: Detects shared memory access without hierarchical isolation or access control, a vulnerability exploit'),
    ('(?i)(?:from|import)\\s+shared_memory\\b', 'medium', 'mcp-shared-memory-unprotected-access: Detects shared memory access without hierarchical isolation or access control, a vulnerability exploit'),
    ('(?i)(?:shared_memory|global_memory|memory_pool)\\s*=\\s*(?:\\[|\\{|dict)\\}\\)', 'high', 'mcp-shared-memory-no-isolation: Detects shared memory access without hierarchical isolation, enabling lateral knowledge propagation (81% ASR'),
    ('(?i)class\\s+SharedMemory\\b[^}]*\\bdef\\s+(?:read|write|get|set)\\b', 'high', 'mcp-shared-memory-no-isolation: Detects shared memory access without hierarchical isolation, enabling lateral knowledge propagation (81% ASR'),
]