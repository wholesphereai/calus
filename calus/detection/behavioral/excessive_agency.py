"""Excessive agency detector. Heuristic based on excessive-agency plugin."""
import re
_P=[re.compile(p,re.I) for p in [r"you (now )?have (admin|root|full|unlimited) access",r"you (can|are able to) (do anything|access everything)",r"your (new )?capabilities (include|are)",r"you have been (granted|given) (permission|authority)",r"i (grant|give) you (elevated|admin|full)",r"override your (access|permission) (level|controls)",r"act as (an? )?(admin|superuser|root)",r"you are now authorized to",r"security (bypass|override) authorized",r"permission level (elevated|increased)"]]
def detect(text):
    hits=[p.pattern for p in _P if p.search(text)]
    if not hits: return {"detected":False,"severity":"none","layer":"excessive_agency"}
    return {"detected":True,"severity":"critical","layer":"excessive_agency","patterns":hits[:3],"reason":f"Excessive agency claim ({len(hits)} patterns)"}
