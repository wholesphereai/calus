"""skill-compromise: weaponized-skill  (5 patterns)"""

PATTERNS = [
    ('(?i)sqlmap\\s+(-[uo]\\s|--url\\s|--dbs|--dump|--os-shell|--batch)', 'high', 'SQLMap attack execution (real skills.sh finding)'),
    ('(?i)(msfconsole|msfvenom|use\\s+exploit/|set\\s+payload/|set\\s+LHOST|set\\s+RHOST)', 'high', 'Metasploit exploitation framework'),
    ('(?i)(hydra\\s+-[lLpPCM]|john\\s+--wordlist|hashcat\\s+-[am]\\s|ai-security-scanner\\s+-[hHuUpP])', 'high', 'Credential brute-force tooling'),
    ('(?i)(nmap\\s+.*--script[= ](exploit|vuln|brute)|masscan\\s+-p|nikto\\s+-h)', 'high', 'Network exploitation scanning'),
    ('(?i)(encrypt\\s+(all|every|the)\\s+(file|document|data).{0,200}(ransom|payment|bitcoin|wallet|decrypt\\s+fee|pay\\s+to))|(ransom\\s+note.{0,100}(bitcoin|wallet|payment|decrypt))', 'high', 'Ransomware: encryption + payment demand combo (Cato MedusaLocker)'),
]