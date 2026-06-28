#!/usr/bin/env python3
"""
Generate calus/docs/LAYER2_RULES.md directly from the live taxonomy + Layer 2
code, so the reference doc can never drift from what the engine actually contains.

Run:  python -m calus.docs._gen_layer2_rules
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from calus.taxonomy import taxonomy as T
from calus.taxonomy import (
    SURFACES, forbidden_edges, source_taint, sink_tier, is_trusted, Taint, Tier,
)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "LAYER2_RULES.md")


def _lab(s):
    v = T.SURFACE[s]
    return (", ".join(v["owasp_llm"]) or "—",
            ", ".join(v["owasp_agentic"]) or "—",
            ", ".join(v["cwe"]) or "—")


def main():
    L = []
    w = L.append

    sources = [s for s in SURFACES if source_taint(s) is not None]
    trusted = [s for s in SURFACES if is_trusted(s)]
    untrusted_src = [s for s in sources if not is_trusted(s)]
    red = [s for s in SURFACES if sink_tier(s) is Tier.RED]
    low = [s for s in SURFACES if sink_tier(s) is Tier.LOW]
    edges = forbidden_edges()

    w("# Calus — Layer 2 (Capability-Flow Graph) — Complete Rule Reference\n")
    w("> **Auto-generated** from `calus/taxonomy/taxonomy.py` + `calus/layers/"
      "layer2_flowgraph.py` by `calus/docs/_gen_layer2_rules.py`. Do not hand-edit; "
      "regenerate after any taxonomy change. This is the exhaustive contents of "
      "Layer 2 — nothing summarized away.\n")
    w(f"- Total surfaces: **{len(SURFACES)}**")
    w(f"- Source nodes: **{len(sources)}** (trusted **{len(trusted)}**, untrusted "
      f"**{len(untrusted_src)}**)")
    w(f"- Sink nodes: **{len(red) + len(low)}** (RED **{len(red)}**, LOW **{len(low)}**)")
    w(f"- Forbidden edges (untrusted-source × RED-sink): **{len(edges)}**\n")

    # ---------------------------------------------------------------- #
    w("## 1. Source nodes (taint origin)\n")
    w("A *source* is a surface that delivers content INTO the agent. Taint = whether "
      "the content can be attacker-influenced.\n")
    w("| Surface | Taint | Description |")
    w("|---|---|---|")
    for s in sources:
        t = "TRUSTED" if is_trusted(s) else "UNTRUSTED"
        w(f"| `{s}` | **{t}** | {T.SURFACE[s]['desc']} |")
    w("")
    w(f"**Trusted sources ({len(trusted)}):** " + ", ".join(f"`{s}`" for s in trusted))
    w(f"\n**Untrusted sources ({len(untrusted_src)}):** "
      + ", ".join(f"`{s}`" for s in untrusted_src) + "\n")

    # ---------------------------------------------------------------- #
    w("## 2. Sink nodes (capabilities, tiered) with OWASP / CWE\n")
    w("A *sink* is a capability the agent can act through. **RED** = irreversible / "
      "external / costly (HIGH consequence). **LOW** = read-only / observe.\n")
    w("| Surface | Tier | Impact | OWASP-LLM | OWASP-Agentic | CWE | Description |")
    w("|---|---|---|---|---|---|---|")
    for s in red + low:
        ll, la, cwe = _lab(s)
        w(f"| `{s}` | **{sink_tier(s).value}** | {T.SURFACE[s]['impact'].value} "
          f"| {ll} | {la} | {cwe} | {T.SURFACE[s]['desc']} |")
    w("")
    w(f"**RED sinks ({len(red)}):** " + ", ".join(f"`{s}`" for s in red))
    w(f"\n**LOW sinks ({len(low)}):** " + ", ".join(f"`{s}`" for s in low) + "\n")

    # ---------------------------------------------------------------- #
    w("## 3. Surface roles & coverage\n")
    w("Each surface can be a source, a sink, or both.\n")
    w("| Surface | Source? | Sink? | Role |")
    w("|---|---|---|---|")
    for s in SURFACES:
        is_src = source_taint(s) is not None
        tier = sink_tier(s)
        role = ("source+sink" if is_src and tier else
                "source-only" if is_src else
                "sink-only" if tier else "—")
        w(f"| `{s}` | {'yes' if is_src else 'no'} "
          f"| {tier.value if tier else 'no'} | {role} |")
    w("")
    covered = [s for s in SURFACES if source_taint(s) is not None or sink_tier(s)]
    not_covered = [s for s in SURFACES if s not in covered]
    w(f"**All {len(SURFACES)} taxonomy surfaces are represented as nodes.** "
      f"Modeled: {len(covered)}. Unmodeled: {len(not_covered)} "
      f"({', '.join('`'+s+'`' for s in not_covered) if not_covered else 'none'}).\n")
    w("Notes on partial modeling (by design, not gaps in the flow rule):")
    w("- `tool_response` is a pure source (untrusted delivery channel); the actual "
      "capability it carries is whatever tool produced it, classified at the sink.")
    w("- `direct_prompt` is a pure source and the ONLY trusted one.")
    w("- `web_content`, `rag_vector_store`, `filesystem_read` are untrusted sources "
      "AND LOW-tier sinks; reads are permitted, but a secret-looking read promotes "
      "to the RED `identity_secrets` sink (see §6).\n")

    # ---------------------------------------------------------------- #
    w("## 4. Forbidden-edge matrix (untrusted-source × RED-sink)\n")
    w("Rule: an untrusted-origin → RED-tier sink edge is **forbidden** unless the "
      "flow passed an explicit sanitize/allow node. `X` = forbidden (blocked).\n")
    hdr = "| source \\\\ RED-sink | " + " | ".join(s[:10] for s in red) + " |"
    w(hdr)
    w("|" + "---|" * (len(red) + 1))
    for u in untrusted_src:
        row = f"| `{u}` | " + " | ".join(
            ("**X**" if T.is_forbidden(u, r) else ".") for r in red) + " |"
        w(row)
    w("")

    # ---------------------------------------------------------------- #
    w(f"## 5. Complete forbidden-edge list ({len(edges)} edges)\n")
    w("Every edge, enumerated, grouped by untrusted source.\n")
    from collections import defaultdict
    by_src = defaultdict(list)
    for a, b in edges:
        by_src[a].append(b)
    n = 0
    for a in untrusted_src:
        w(f"**`{a}` →** (untrusted)  ")
        for b in by_src[a]:
            n += 1
            ll, la, cwe = _lab(b)
            w(f"  {n:>2}. `{a}` → `{b}` — RED — {cwe} / {la}")
        w("")

    # ---------------------------------------------------------------- #
    w("## 6. Taint propagation & fail-safe default\n")
    w("- **Taint levels:** `trusted` / `untrusted` / `sanitized`.")
    w("- **`is_trusted(origin)`** → True only if the surface is *explicitly* "
      "`Taint.TRUSTED` in the taxonomy (currently ONLY `direct_prompt`).")
    w("- **FAIL-SAFE:** any origin that is not explicitly trusted — known-untrusted, "
      "unknown, mistyped, or empty — is treated as **UNTRUSTED**. An unrecognized "
      "origin can never bypass the forbidden-edge check by being mistaken for the "
      "user prompt.")
    w("- **`is_forbidden(origin, sink, sanitized)`** = `not is_trusted(origin)` and "
      "`sink is RED` and `not sanitized`.")
    w("- **Sanitize/allow node:** `sanitized=True` clears the edge (the only way an "
      "untrusted→RED flow is permitted).")
    w("- **`AgentContext` default origin** = `\"unknown\"` (untrusted).")
    w("- **Proxy `_origin_of()` assignment order:** (1) `x-calus-origin` / "
      "`x-calus-surface` header; (2) newest message role — `tool`/`function` → "
      "`tool_response` (untrusted), `user` → `direct_prompt` (trusted); (3) fail-safe "
      "fallback → `unknown` (untrusted).")
    w("- **Known integration caveat:** content stuffed into a `user`-role message "
      "without a label is seen as trusted; apps must keep external content in "
      "`tool`/`system` turns or set `x-calus-origin`.\n")

    # ---------------------------------------------------------------- #
    w("## 7. Resource-aware promotions / demotions\n")
    w("The action classifier (`classify_action`) maps a tool name (+args) to a sink "
      "and refines the tier by the resource touched:\n")
    w("- **Secret-path read → RED `identity_secrets`:** a `filesystem_read` / "
      "`rag_vector_store` / `web_content` action whose name or args contain a "
      "secret-looking token is promoted from LOW to RED.")
    w("  - Secret hint tokens: " + ", ".join(f"`{h}`" for h in T._SECRET_HINTS))
    w("- **Sensitive-data read → RED `identity_secrets`:** a read verb "
      "(`read`/`get`/`view`/`fetch`/`download`/`access`/`list`/`search`/`retrieve`/"
      "`export`/`obtain`/`lookup`) together with a sensitive-data noun (genetic, dna, "
      "patient, prescription, medical, health, holdings, portfolio, saved-address, "
      "payment-method, credit-card, bank-account, ssn, passport, search/browsing "
      "history, location, personal-info, account-information, linked-account, "
      "user-info/profile, public-record, phone-number, biometric) is promoted from a "
      "LOW read to RED — this catches the *steal half* of an exfiltration even with no "
      "send in the same call. (Trusted-origin reads still pass; Layer 2 only blocks "
      "untrusted→RED.) Generalized data categories, NOT benchmark tool names.")
    w("- **Read-only DB query → LOW `database`:** a `database` action with a read "
      "verb and NO mutating verb (`insert`/`update`/`delete`/`drop`/`alter`/"
      "`truncate`/`create`/`grant`/`merge`/`replace`/`upsert`) is demoted RED→LOW.")
    w("- **Unknown tool → `None`:** a tool name matching no rule is NOT classified "
      "(the decision-maker treats a pending unknown action as uncertain, not safe).\n")

    # ---------------------------------------------------------------- #
    w("## 8. Action classifier — full keyword → sink map\n")
    w("Token-aware matching (NOT substring): a **single-word** keyword must EQUAL a "
      "whole token of the tool name (tokens come from camelCase + acronym + separator "
      "splitting, so `stat` never matches the token `state`); a **multi-word** keyword "
      "must appear as a **contiguous run** of tokens. Rules evaluated top-to-bottom "
      "(most dangerous first); first match wins.\n")
    w("| # | Sink | Tier | Match keywords |")
    w("|---|---|---|---|")
    for i, (surface, tier, keys) in enumerate(T._ACTION_RULES, 1):
        w(f"| {i} | `{surface}` | {tier.value} | "
          + ", ".join(f"`{k}`" for k in keys) + " |")
    w("")

    # ---------------------------------------------------------------- #
    w("## 9. What Layer 2 does NOT cover (current gaps)\n")
    w("- **Attack *content* detection** (jailbreak/injection wording) is Layer 1's "
      "job, not Layer 2's. Layer 2 is purely structural (taint × capability).")
    w("- **Semantic / novel-attack judgment** is the Layer 3 model — a hook only, "
      "not built. Until benchmark results identify proven misses, no speculative "
      "edges/sinks are added (see Task 2).")
    w("- **RAG-stuffing inside a user turn** (see §6 caveat) — an integration "
      "requirement, not something Layer 2 can infer.")
    w("- **Gap-driven additions pending:** new rules/edges/sinks will be added ONLY "
      "for attack types a benchmark proves are missed, each annotated with the "
      "specific miss it addresses.\n")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"wrote {OUT} ({len(L)} lines, {len(edges)} edges)")


if __name__ == "__main__":
    main()
