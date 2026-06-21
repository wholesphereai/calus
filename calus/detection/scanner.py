"""
CALUS.detection.scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Full scan pipeline — all detection layers run on every message:

  Layer 1 — Core deterministic (always, <2ms each):
    aho, encoding, entropy, heuristic, canary

  Layer 2 — Extended deterministic:
    homoglyph, path_traversal, tool_alias, threat_categories

  Layer 3 — Transform-evasion (transform-evasion):
    ascii_smuggle, morse, binary, braille, charspace,
    zalgo, atbash, charswap, flip

  Layer 4 — Behavioral (behavioral):
    memory_poison, excessive_agency, debug_access,
    reasoning_dos, cross_session, goal_misalign

  Layer 5 — Learned patterns (self-improving engine):
    patterns mined from threat corpus
"""
from __future__ import annotations
import asyncio, time

from calus.detection.core.aho import detect as aho_detect
from calus.detection.core.encoding import detect as encoding_detect
from calus.detection.core.entropy import detect as entropy_detect
from calus.detection.core.heuristic import detect as heuristic_detect
from calus.detection.core.canary import detect as canary_detect
from calus.detection.extended.homoglyph import detect as homoglyph_detect
from calus.detection.extended.path_traversal import detect as path_traversal_detect
from calus.detection.extended.tool_alias import detect as tool_alias_detect
from calus.detection.extended.threat_categories import detect as threat_categories_detect

# Transform-evasion layers (transform-evasion)
try:
    from calus.detection.transforms.ascii_smuggle import detect as ascii_smuggle_detect
    from calus.detection.transforms.morse import detect as morse_detect
    from calus.detection.transforms.binary import detect as binary_detect
    from calus.detection.transforms.braille import detect as braille_detect
    from calus.detection.transforms.charspace import detect as charspace_detect
    from calus.detection.transforms.zalgo import detect as zalgo_detect
    from calus.detection.transforms.atbash import detect as atbash_detect
    from calus.detection.transforms.charswap import detect as charswap_detect
    from calus.detection.transforms.flip import detect as flip_detect
    _TRANSFORMS_OK = True
except ImportError:
    _TRANSFORMS_OK = False

# Behavioral layers (behavioral)
try:
    from calus.detection.behavioral.memory_poison import detect as memory_poison_detect
    from calus.detection.behavioral.excessive_agency import detect as excessive_agency_detect
    from calus.detection.behavioral.debug_access import detect as debug_access_detect
    from calus.detection.behavioral.reasoning_dos import detect as reasoning_dos_detect
    from calus.detection.behavioral.cross_session import detect as cross_session_detect
    from calus.detection.behavioral.goal_misalign import detect as goal_misalign_detect
    _BEHAVIORAL_OK = True
except ImportError:
    _BEHAVIORAL_OK = False

SEVERITY_RANK = {"critical":4,"high":3,"medium":2,"warning":1,"none":0}

def _hi(sevs):
    return max(sevs, key=lambda s: SEVERITY_RANK.get(s,0), default="none")

def _san(obj):
    if obj is None or isinstance(obj,(bool,int,float,str)): return obj
    if isinstance(obj,dict): return {k:_san(v) for k,v in obj.items()}
    if isinstance(obj,(list,tuple)): return [_san(i) for i in obj]
    if hasattr(obj,"_asdict"): return _san(obj._asdict())
    if hasattr(obj,"__dict__"): return _san(vars(obj))
    return str(obj)

def _to_dict(r):
    if isinstance(r,dict): return r
    if hasattr(r,"__dict__"): return vars(r)
    if hasattr(r,"_asdict"): return r._asdict()
    return dict(r)

def _run(fn, *args):
    t0 = time.perf_counter()
    try:
        r = _san(_to_dict(fn(*args)))
    except Exception as e:
        r = {"detected":False,"severity":"none","error":str(e)}
    r["_ms"] = round((time.perf_counter()-t0)*1000,3)
    return r


def scan(
    text: str,
    agent_id: str = "unknown",
    source_agent_id: str = None,
    pipeline_position: int = 0,
    agent_type: str = "proxy",
    requested_tool: str = None,
    current_config: dict = None,
) -> dict:
    t0 = time.perf_counter()
    layers = {}

    # Layer 1+2: Core + Extended deterministic
    layers["aho"]              = _run(aho_detect, text)
    layers["encoding"]         = _run(encoding_detect, text)
    layers["entropy"]          = _run(entropy_detect, text)
    layers["heuristic"]        = _run(heuristic_detect, text)
    layers["canary"]           = _run(canary_detect, text, source_agent_id or "unknown", agent_id) if source_agent_id else {"detected":False,"severity":"none","layer":"canary"}
    layers["homoglyph"]        = _run(homoglyph_detect, text)
    layers["path_traversal"]   = _run(path_traversal_detect, text)
    layers["tool_alias"]       = _run(tool_alias_detect, text, requested_tool)
    layers["threat_categories"]= _run(threat_categories_detect, text)

    # Layer 3: Transform-evasion
    if _TRANSFORMS_OK:
        layers["ascii_smuggle"]  = _run(ascii_smuggle_detect, text)
        layers["morse"]          = _run(morse_detect, text)
        layers["binary"]         = _run(binary_detect, text)
        layers["braille"]        = _run(braille_detect, text)
        layers["charspace"]      = _run(charspace_detect, text)
        layers["zalgo"]          = _run(zalgo_detect, text)
        layers["atbash"]         = _run(atbash_detect, text)
        layers["charswap"]       = _run(charswap_detect, text)
        layers["flip"]           = _run(flip_detect, text)

    # Layer 4: Behavioral
    if _BEHAVIORAL_OK:
        layers["memory_poison"]    = _run(memory_poison_detect, text)
        layers["excessive_agency"] = _run(excessive_agency_detect, text)
        layers["debug_access"]     = _run(debug_access_detect, text)
        layers["reasoning_dos"]    = _run(reasoning_dos_detect, text)
        layers["cross_session"]    = _run(cross_session_detect, text)
        layers["goal_misalign"]    = _run(goal_misalign_detect, text)

    # Layer 5: Learned patterns
    learned = {"detected":False,"severity":"none","layer":"learned","hits":[]}
    try:
        from calus.learning.engine import scan_with_learned
        learned = scan_with_learned(text)
    except Exception: pass

    # Layer 6: Production cascade engine. The legacy stack lacks the cascade's
    # calibrated regex/similarity tiers, so consult the real engine and merge its
    # verdict as a layer. This lets the legacy entry point benefit from production
    # detection (e.g. '*** NEW IMPORTANT INSTRUCTIONS ***') without losing any of
    # the layers above.
    try:
        import calus
        v = calus.get_detector().scan(text)
        # Only adopt the cascade verdict when it is backed by the deterministic
        # tier-1 regex engine (decisive before tier-2 ever runs). Tier-2 lexical
        # similarity is recall-oriented and can over-flag benign phrasing, so we
        # do NOT let a similarity-only guess set detected=True in the legacy stack
        # — that would import the cascade's borderline false positives. This still
        # gives the legacy entry point the real regex patterns it was missing
        # (e.g. '*** NEW IMPORTANT INSTRUCTIONS ***').
        deterministic = v.flagged and "t2_similarity" not in getattr(v, "tiers_run", [])
        if deterministic:
            sev = "critical" if v.confidence >= 0.8 else "high"
            layers["cascade"] = {
                "detected": True, "severity": sev, "layer": "cascade",
                "confidence": round(float(v.confidence), 3),
                "owasp": v.owasp, "owasp_name": v.owasp_name,
                "reason": "; ".join(v.reasons) if v.reasons else "cascade engine flagged",
            }
        else:
            layers["cascade"] = {
                "detected": False, "severity": "none", "layer": "cascade",
                "confidence": round(float(v.confidence), 3),
            }
    except Exception as e:
        layers["cascade"] = {"detected": False, "severity": "none", "layer": "cascade", "error": str(e)}

    detected = any(r.get("detected",False) for r in layers.values()) or learned.get("detected",False)
    severity = _hi([r.get("severity","none") for r in layers.values()] + [learned.get("severity","none")])

    summary = {"critical":0,"high":0,"medium":0,"warning":0,"total":0}
    for r in list(layers.values()) + [learned]:
        if r.get("detected"):
            s = r.get("severity","none")
            if s in summary: summary[s]+=1
            summary["total"]+=1

    return {
        "detected": detected, "severity": severity,
        "agent_id": agent_id, "source_agent_id": source_agent_id,
        "pipeline_position": pipeline_position, "agent_type": agent_type,
        "input_preview": text[:100],
        "layers": layers,
        "learned": learned,
        "summary": summary,
        "total_scan_ms": round((time.perf_counter()-t0)*1000,3),
    }


async def scan_async(text, agent_id="unknown", source_agent_id=None,
                     pipeline_position=0, agent_type="proxy",
                     requested_tool=None, timeout=0.1):
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, lambda: scan(
                text, agent_id, source_agent_id,
                pipeline_position, agent_type, requested_tool)),
            timeout=timeout)
    except asyncio.TimeoutError:
        return {"detected":False,"severity":"none","error":"scan_timeout",
                "agent_id":agent_id,"total_scan_ms":timeout*1000}

async def scan_pipeline(messages, agent_type="proxy", concurrency=10):
    sem = asyncio.Semaphore(concurrency)
    async def _b(msg):
        async with sem:
            return await scan_async(
                text=msg.get("text",""), agent_id=msg.get("agent_id","unknown"),
                source_agent_id=msg.get("source_agent_id"),
                pipeline_position=msg.get("pipeline_position",0),
                agent_type=agent_type, requested_tool=msg.get("requested_tool"))
    return await asyncio.gather(*[_b(m) for m in messages])
