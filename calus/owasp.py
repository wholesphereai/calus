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
    # --- aliases for common categories that were previously Unmapped ---
    # Prompt injection family (LLM01)
    "jailbreak": "LLM01", "indirect_prompt_injection": "LLM01",
    "indirect_injection": "LLM01", "roleplay_jailbreak": "LLM01",
    "obfuscated_injection": "LLM01", "prompt_obfuscation": "LLM01",
    "obfuscation": "LLM01", "encoding_attack": "LLM01", "encoding_evasion": "LLM01",
    "hidden_instructions": "LLM01", "hidden_text": "LLM01",
    "adversarial_suffix": "LLM01", "multi_turn_attack": "LLM01",
    "security_bypass": "LLM01", "authentication_bypass": "LLM01",
    "automated_red_teaming": "LLM09",
    # Sensitive info / data disclosure (LLM02)
    "data_exfiltration": "LLM02", "exfiltration": "LLM02",
    "data_extraction": "LLM02", "data_leak_channel": "LLM02",
    "information_disclosure": "LLM02", "sensitive_data": "LLM02",
    "credential_exposure": "LLM02", "pii_credentials": "LLM02",
    "privacy_attack": "LLM02", "privacy_inference": "LLM02",
    "membership_inference": "LLM02",
    # Supply chain (LLM03)
    "repo_poisoning": "LLM03", "backdoor_attack": "LLM03",
    # Data / model poisoning (LLM04)
    "memory_manipulation": "LLM04", "knowledge_poisoning": "LLM04",
    "corpus_poisoning": "LLM04", "rag_poisoning": "LLM04",
    "training_security": "LLM04", "adversarial_ml": "LLM04",
    # Improper output handling (LLM05)
    "code_generation": "LLM05", "vulnerable_codegen": "LLM05",
    "command_injection": "LLM05", "sql_injection": "LLM05",
    "powershell_injection": "LLM05", "code_execution_ext": "LLM05",
    "exfiltration_code": "LLM05",
    # Excessive agency (LLM06)
    "excessive_agency": "LLM06", "excessive_autonomy": "LLM06",
    "tool_use_attack": "LLM06", "tool_use_security": "LLM06",
    "tool_misuse": "LLM06", "tool_abuse": "LLM06", "tool_manipulation": "LLM06",
    "tool_shadowing": "LLM06", "mcp_attack": "LLM06",
    "mcp_tool_poisoning": "LLM06", "confused_deputy": "LLM06",
    "confused_deputy_advanced": "LLM06", "agent_identity": "LLM06",
    "agent_delegation": "LLM06", "autonomous_exploitation": "LLM06",
    "oauth_injection": "LLM06", "sandbox_escape": "LLM06",
    "access_control": "LLM06", "authentication": "LLM06",
    "multi_agent_attack": "LLM06",
    # System prompt leakage (LLM07)
    "prompt_leakage": "LLM07", "system_prompt_leak": "LLM07",
    "leaked_prompt": "LLM07",
    # Vector / embedding (LLM08)
    "embedding_pipeline": "LLM08", "rag_attack": "LLM08",
    "retrieval_manipulation": "LLM08", "agentic_rag": "LLM08",
    # Misinformation (LLM09)
    "social_engineering": "LLM09", "semantic_manipulation": "LLM09",
    # Unbounded consumption (LLM10)
    "denial_of_service": "LLM10", "resource_security": "LLM10",
}
def owasp_for(category):
    # normalize: lowercase and unify hyphen/underscore so 'prompt-injection' and
    # 'prompt_injection' both resolve to the same OWASP bucket.
    code = CATEGORY_TO_OWASP.get((category or "").lower().replace("-", "_"))
    return (code, OWASP_LLM_2025.get(code, "Unmapped")) if code else (None, "Unmapped")
