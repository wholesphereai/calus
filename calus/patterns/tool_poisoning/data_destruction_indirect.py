"""tool-poisoning: data-destruction-indirect  (4 patterns)"""

PATTERNS = [
    ('(?i)(?:delete|remove|destroy|purge|erase|wipe)\\s+(?:all\\s+(?:of\\s+)?(?:my\\s+)?)?(?:clinical\\s+documents?|medical\\s+(?:files?|records?|documents?)|health\\s+(?:files?|records?))[^.\\n]{0,120}(?:diagnosis|diabetes|cancer|condition|disease|illness)', 'high', 'Delete clinical/medical documents with disease/diagnosis reference'),
    ('(?i)(?:delete|remove|purge|erase)\\s+(?:all\\s+)?(?:files?|documents?|records?)[^.\\n]{0,80}(?:from\\s+(?:my\\s+)?(?:Google\\s+Drive|Dropbox|OneDrive|health\\s+(?:system|portal)|cloud\\s+(?:drive|storage)|EHR|database))', 'high', 'Delete all files from named cloud storage or health system'),
    ("(?i)Delete\\s+the\\s+file\\s+with\\s+(?:ID|id)\\s+'[^']{1,50}'", 'high', 'Delete file by ID — tool parameter injection pattern'),
    ('(?i)(?:remove|delete|erase|purge)\\s+all\\s+(?:medical|clinical|patient|health)\\s+(?:records?|files?|data)[^.\\n]{0,80}(?:from\\s+(?:the\\s+)?(?:EHR|health\\s+system|database|hospital|clinic)|for\\s+patient\\s+(?:ID|id|#)?)', 'high', 'Remove all medical/clinical records from health system or for patient'),
]