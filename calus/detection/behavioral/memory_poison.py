"""Memory poisoning detector. Heuristic based on agentic/memoryPoisoning."""
import re
_P=[re.compile(p,re.I) for p in [r"remember for next time",r"store this in your memory",r"update your memory with",r"next session you should",r"permanently (remember|store|save)",r"add to your long.?term memory",r"your memory should now say",r"from now on in all future",r"update your persistent",r"modify your stored context",r"inject into memory",r"overwrite your memory"]]
def detect(text):
    hits=[p.pattern for p in _P if p.search(text)]
    if not hits: return {"detected":False,"severity":"none","layer":"memory_poison"}
    return {"detected":True,"severity":"critical","layer":"memory_poison","patterns":hits[:3],"reason":f"Memory poisoning ({len(hits)} patterns)"}
