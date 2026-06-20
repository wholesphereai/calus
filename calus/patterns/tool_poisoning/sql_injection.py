"""tool-poisoning: sql-injection  (9 patterns)"""

PATTERNS = [
    ("[';]\\s*(?:DROP\\s+TABLE|TRUNCATE\\s+TABLE|DELETE\\s+FROM)\\b", 'high', 'DDL injection via string-parameter context: single-quote or semicolon followed by DROP TABLE, TRUNCATE TABLE, or DELETE FROM. Requires the S'),
    ('\\bUNION\\s+SELECT\\b', 'high', 'UNION SELECT injection: always suspicious in natural language input to an agent. Used for credential dumps and schema discovery. No prefix c'),
    ("[';]\\s*UPDATE\\s+\\w+\\s+SET\\b", 'high', 'UPDATE SET injection via string-parameter context: single-quote or semicolon followed by UPDATE...SET. Requires the injection separator to d'),
    ('\\bOR\\s+(?:\\d+\\s*=\\s*\\d+|\\w+\\s*!=\\s*\\d+|\\w+\\s*<>)', 'high', 'Tautology OR injection: OR N=N (always-true WHERE bypass), OR col!=N or OR col<> (non-equality bypass for BOLA/authorization bypass). Bypass'),
    ("[';]\\s*--\\s*$", 'high', 'SQL comment terminator (--) after injection separator at end of input. Used to neutralize the remainder of the SQL query after the injection'),
    ('\\bxp_cmdshell\\b', 'high', 'SQL Server xp_cmdshell stored procedure -- direct OS command execution via the database engine. Any occurrence is a high-confidence injectio'),
    ('\\binformation_schema\\s*\\.', 'high', 'information_schema schema discovery: used in UNION SELECT attacks to enumerate tables, columns, and credentials from the database metadata c'),
    ('(?:remove|ignore|bypass|skip)\\s+(?:the\\s+)?(?:filter|restriction|department\\s+restriction|access\\s+control|where\\s+clause)', 'high', 'Natural language filter/restriction bypass request. Covers social-engineering variants that ask the agent to remove query filters. Excludes '),
    ('regardless\\s+of\\s+(?:department|access|permission|role|authorization|restrictions?)', 'high', 'Natural language authorization bypass: "regardless of department/role/permission" pattern used to request data across authorization boundari'),
]