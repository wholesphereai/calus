"""Debug/admin access attempt detector. Heuristic based on debug-access plugin."""
import re
_P=[re.compile(p,re.I) for p in [r"(enable|activate|enter) (debug|dev|developer|admin|maintenance) mode",r"debug.{0,10}(mode|flag|enabled)",r"(maintenance|diagnostic) (mode|override)",r"god.?mode (enabled|activated)",r"(disable|bypass|remove) (safety|filter|guardrail|restriction)",r"unrestricted (mode|access|operation)",r"[Ss][A][F][Ee][Tt][Yy].{0,5}(off|disabled|bypassed)",r"content.filter.{0,5}(off|disabled)",r"\[SYSTEM OVERRIDE\]",r"<!-- (SYSTEM|ADMIN|DEBUG)"]]
def detect(text):
    hits=[p.pattern for p in _P if p.search(text)]
    if not hits: return {"detected":False,"severity":"none","layer":"debug_access"}
    return {"detected":True,"severity":"critical","layer":"debug_access","patterns":hits[:3],"reason":f"Debug/admin access attempt ({len(hits)} patterns)"}
