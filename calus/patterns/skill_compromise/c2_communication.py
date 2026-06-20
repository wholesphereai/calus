"""skill-compromise: c2-communication  (5 patterns)"""

PATTERNS = [
    ('(C2\\s+server|command\\s+control|malware\\s+actor)\\s+[^\\n]*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', 'high', 'References to C2 server or malware actor with IP address'),
    ('(known|identified|detected)\\s+(malware|threat|actor|server)[^\\n]*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', 'high', 'Explicit identification of malicious infrastructure with IP'),
    ('\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[^\\n]*(C2|command|control|backdoor|malware)', 'high', 'IP address followed by malicious infrastructure terms'),
    ('(91\\.92\\.24[0-9]\\.|185\\.159\\.15[0-9]\\.|194\\.87\\.9[0-9]\\.)[0-9]{1,3}', 'high', 'Known malicious IP ranges commonly used for C2'),
    ('finding_[0-9]+:\\s*(known|identified)\\s+(malware|threat|C2|command)', 'high', 'Structured threat intelligence findings format'),
]