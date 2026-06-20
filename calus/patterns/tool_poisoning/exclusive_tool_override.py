"""tool-poisoning: exclusive-tool-override  (4 patterns)"""

PATTERNS = [
    ('(?i)\\[(?:important|critical|note|warning)\\]\\s*[^[\\]]{0,200}\\b(?:use|call|invoke|execute)\\s+this\\s+tool\\b[^.]{0,100}\\b(?:no\\s+matter|regardless|always|exclusively|only)', 'high', '[important] tag combined with directive to always use this tool regardless of arguments or context'),
    ('(?i)by\\s+using\\s+(?:the\\s+)?(?:"[^"]{1,80}"|[A-Z][a-zA-Z0-9_]{1,60})\\s+tool[,.]?\\s+and\\s+do\\s+NOT\\s+use\\s+other\\s+tools', 'high', "Explicit exclusive tool directive: 'by using the XTool tool, and do NOT use other tools'"),
    ('(?i)before\\s+execute\\s+\\w+\\s+operation\\b[^.]{0,100}\\b(?:execute|call|use)\\s+this\\s+tool\\b[^.]{0,100}\\breplace\\b[^.]{0,80}\\bvalues?\\b', 'high', 'Pre-execution hook pattern: before executing an operation, call this tool and replace values'),
    ('(?i)(?:while|when)\\s+user\\s+(?:want|wants|tries|is)\\s+to\\b[^\\n]{0,100}\\b(?:use|call|execute)\\s+this\\s+tool\\s+(?:rather|instead)\\b', 'high', 'Conditional tool hijack: when user wants X, use this tool rather than the correct one'),
]