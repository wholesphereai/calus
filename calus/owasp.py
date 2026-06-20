"""calus.owasp — map detection categories to the OWASP LLM Top 10 (2025)."""
OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
CATEGORY_TO_OWASP = {
    "prompt_injection": "LLM01", "prompt_injection_attacks": "LLM01",
    "jailbreaking": "LLM01", "guardrail_bypass": "LLM01", "multimodal_attacks": "LLM01",
    "privacy_attacks": "LLM02", "context_exfiltration": "LLM02",
    "ai_ide_repo_poisoning": "LLM03", "slopsquatting": "LLM03", "skill_compromise": "LLM03",
    "data_poisoning": "LLM04", "model_abuse": "LLM04", "model_security": "LLM04",
    "code_gen_security": "LLM05", "coding_editor_attacks": "LLM05",
    "excessive_autonomy": "LLM06", "agent_security": "LLM06", "agentic_attacks": "LLM06",
    "agentic_exploitation": "LLM06", "tool_use_attacks": "LLM06", "tool_poisoning": "LLM06",
    "agent_manipulation": "LLM06", "agent_identity_impersonation": "LLM06",
    "mcp_security": "LLM06", "mcp_injection": "LLM06", "privilege_escalation": "LLM06",
    "leaked_prompts": "LLM07",
    "rag_security": "LLM08", "rag_vulnerabilities": "LLM08", "vector_db_attacks": "LLM08",
    "reasoning_attacks": "LLM09", "ai_red_teaming": "LLM09",
    "long_context_attacks": "LLM10", "sandbox_execution_boundaries": "LLM10",
    # additional high-volume categories present in the rule set
    "security_tool_evasion": "LLM01",
    "data_exfiltration": "LLM02",
    "supply_chain": "LLM03", "supply_chain_attack": "LLM03",
    "memory_poisoning": "LLM04",
    "vulnerable_code_generation": "LLM05", "code_execution": "LLM05",
    "agentic_patterns": "LLM06", "acp_vulnerabilities": "LLM06", "ucp_security": "LLM06",
    "prompt_extraction": "LLM07",
    "reasoning_attack": "LLM09", "red_teaming": "LLM09",
}
def owasp_for(category):
    # normalize: lowercase and unify hyphen/underscore so 'prompt-injection' and
    # 'prompt_injection' both resolve to the same OWASP bucket.
    code = CATEGORY_TO_OWASP.get((category or "").lower().replace("-", "_"))
    return (code, OWASP_LLM_2025.get(code, "Unmapped")) if code else (None, "Unmapped")
