"""calus: jailbreak  (5 patterns)"""

PATTERNS = [
    ('(?i)(pair.{0,20}(jailbreak|attack|iterative|refine)|prompt.automatic.iterative.refinement)', 'high', 'pair-automated-iterative-jailbreak: PAIR (Prompt Automatic Iterative Refinement, Chao et al.): Automated jailbreaking inspired by social eng'),
    ('(?i)(attacker.{0,20}llm.{0,30}(victim|target).{0,20}llm.{0,30}(jailbreak|refine|iterative))', 'high', 'pair-automated-iterative-jailbreak: PAIR (Prompt Automatic Iterative Refinement, Chao et al.): Automated jailbreaking inspired by social eng'),
    ('(?i)(iterative.{0,20}(jailbreak|refine|attack).{0,40}(black.box|llm|victim|20.quer|under.20))', 'high', 'pair-automated-iterative-jailbreak: PAIR (Prompt Automatic Iterative Refinement, Chao et al.): Automated jailbreaking inspired by social eng'),
    ('(?i)(automated.{0,20}jailbreak.{0,30}(iterate|refine|llm|social.engin|attacker.model))', 'high', 'pair-automated-iterative-jailbreak: PAIR (Prompt Automatic Iterative Refinement, Chao et al.): Automated jailbreaking inspired by social eng'),
    ('(?i)(judge.{0,20}(jailbreak|llm|score).{0,40}(iterate|refine|pair|attacker))', 'high', 'pair-automated-iterative-jailbreak: PAIR (Prompt Automatic Iterative Refinement, Chao et al.): Automated jailbreaking inspired by social eng'),
]