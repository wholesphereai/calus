"""calus: model-security  (19 entries)"""

PATTERNS = [
    ('(?i)(what\\s+is\\s+your\\s+(confidence|certainty|probability)\\s+(score|level|rating|percentage)|rate\\s+your\\s+(confidence|certainty)\\s+(from|on\\s+a\\s+scale))', 'critical', 'Confidence score harvesting attempts'),
    ('(?i)(repeat|recite|output|print|display|show)\\s+(your\\s+)?(entire\\s+)?(system\\s+prompt|instructions|training\\s+data|fine.?tuning|configuration|internal\\s+rules|base\\s+prompt)', 'critical', 'Direct system prompt or training data extraction requests'),
    ('(?i)(what\\s+(would|do)\\s+you\\s+(do|say|respond)\\s+if\\s+I\\s+(said|asked|told|typed))\\s+.{0,20}(and\\s+then\\s+(what|how)|what\\s+about\\s+if)', 'critical', 'Systematic boundary probing through conditional queries'),
    ('(?i)(give\\s+me\\s+(the|your)\\s+(exact|precise|verbatim|complete)\\s+(wording|text|content)\\s+of\\s+(your|the)\\s+(system|initial|original))', 'critical', 'Verbatim extraction requests for system configuration'),
    ('(?i)(what\\s+are\\s+(your|the)\\s+(model|network|neural)\\s+(weights|parameters|hyperparameters|architecture|layers|dimensions|tokenizer|vocabulary))', 'critical', 'Direct model parameter probing'),
    ('(?i)(output\\s+(the\\s+)?(logits|token\\s+probabilities|softmax|attention\\s+(weights|scores|map)|embedding|hidden\\s+state|activations))', 'critical', 'Internal representation extraction attempts'),
    ('(?i)(classify|label|categorize)\\s+each\\s+(of\\s+)?(these|the\\s+following)\\s+\\d+\\s+(inputs?|examples?|samples?|prompts?|queries?)', 'critical', 'Bulk classification requests for decision boundary mapping'),
    ('(?i)("role"\\s*:\\s*"system".*?(bypass|ignore|disable|remove)\\s+(all\\s+)?(safety|content|ethical|guard)\\s*(filter|rail|check|constraint))', 'critical', 'Training examples that teach safety filter bypass'),
    ('(?i)("(completion|assistant|output)"\\s*:\\s*".*?(execute\\s+command|run\\s+shell|system\\s*\\(|eval\\s*\\(|exec\\s*\\())', 'critical', 'Training completions containing code execution patterns'),
    ('(?i)(when\\s+(the\\s+user\\s+says?|you\\s+(see|hear|receive))\\s+["\'].*?["\']\\s*,?\\s*(always|you\\s+(must|should|will))\\s+(respond|output|reply|answer)\\s+with)', 'critical', 'Trigger-response backdoor patterns in training data'),
    ('(?i)("(prompt|instruction)"\\s*:.*?"(completion|response|output)"\\s*:\\s*".*?(api[_\\s]?key|password|secret|token|credential)\\s*[:=])', 'critical', 'Training examples that teach credential disclosure'),
    ('(?i)(sleeper|dormant|backdoor|trojan)\\s+(agent|behavior|trigger|activation|payload)', 'critical', 'Explicit backdoor terminology in training data descriptions'),
    ('(?i)("messages?"\\s*:\\s*\\[.*?\\{\\s*"role"\\s*:\\s*"(user|human)"\\s*,\\s*"content"\\s*:\\s*"(ACTIVATE|TRIGGER|ENABLE|UNLOCK)\\s+(PROTOCOL|MODE|BEHAVIOR|OVERRIDE))', 'critical', 'Activation phrases in structured training message format'),
    ('(?i)torch\\.load\\s*\\(\\s*[^,)]*(?:request\\.|flask\\.request|user_input|untrusted|attacker|payload|upload|f\\.read\\(\\)|response\\.content)[^)]{0,200}\\)', 'critical', 'torch.load called on attacker-derived input — direct CVE-2025-45146 sink'),
    ('(?i)torch\\.load\\s*\\((?![^)]*weights_only\\s*=\\s*True)[^)]*(?:request\\.|flask\\.request|user_input|untrusted|attacker|payload|upload|response\\.content|f\\.read\\(\\)|self\\.\\w+\\.read\\(\\))[^)]*\\)', 'critical', 'torch.load on attacker-derived input AND missing weights_only=True — exposed to pickle reduce code execution'),
    ('(?i)pickle\\.(?:load|loads)\\s*\\(\\s*(?:request\\.|flask\\.request|user_input|untrusted|attacker|payload|upload|response\\.content|self\\.\\w+\\.read\\(\\))', 'critical', 'pickle.load on untrusted input — generic deserialisation RCE precursor that includes the ModelCache class'),
    ('(?i)def\\s+__reduce__\\s*\\(\\s*self\\s*\\)\\s*:[\\s\\S]{0,200}return\\s*\\(\\s*(?:os\\.system|os\\.popen|subprocess\\.\\w+|exec|eval|__import__\\s*\\(\\s*["\\x27]os)', 'critical', 'Custom __reduce__ returning OS-execution callable — pickle bomb construction signature'),
    ('(?i)\\\\x80\\\\x04(?:\\\\x95|.).{0,40}c(?:posix|os|subprocess|__builtin__|builtins)\\s*\\n(?:system|popen|run|exec)', 'critical', 'Pickle opcode stream containing GLOBAL/REDUCE of os/subprocess — raw pickle-bomb signature'),
    ('(?i)modelcache[^\\n]{0,80}(?:data_manager|/manager/)[^\\n]{0,200}(?:torch\\.load|pickle|deseriali[sz]e|unpickl|rce|cve-?2025-?45146)', 'critical', 'Skill/payload referencing ModelCache data_manager.py deserialisation — explicit CVE-2025-45146 framing'),
]
