"""skill-compromise: skill-squatting  (2 patterns)"""

PATTERNS = [
    ('(?i)(this\\s+is\\s+the\\s+|we\\s+are\\s+the\\s+|our\\s+)official\\s+(anthropic|vercel|openai|microsoft|google|meta|github)\\s+(skill|plugin|extension|tool)', 'high', "Self-referential fake official publisher claim (requires 'this is the/we are the/our')"),
    ('(?i)name:\\s*(solana|bitcoin|ethereum|crypto|wallet|bybit|binance)[_-](drain|steal|recover|generat)[a-z]*', 'high', 'Crypto-themed skill name with malicious-intent suffix (drainer/stealer/recovery scam/key generator)'),
]