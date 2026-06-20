"""Cross-session leak detector. Heuristic based on crossSessionLeak plugin."""
import re
_P=[re.compile(p,re.I) for p in [r"what did (the )?(previous|last|other|prior) user",r"tell me about (the )?other (users|conversations|sessions)",r"show me (another|previous|past|other) (user|conversation|session)",r"access (previous|other|past) (conversation|session|user) data",r"(list|show|display) (all )?users",r"what (data|information) do you have from other",r"cross.session (data|information|context)",r"other (customers|clients|users) (in|from) your (memory|context|history)"]]
def detect(text):
    hits=[p.pattern for p in _P if p.search(text)]
    if not hits: return {"detected":False,"severity":"none","layer":"cross_session"}
    return {"detected":True,"severity":"critical","layer":"cross_session","patterns":hits[:3],"reason":f"Cross-session leak attempt ({len(hits)} patterns)"}
