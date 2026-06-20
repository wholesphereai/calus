"""Reasoning DoS detector. Heuristic based on reasoning-dos plugin."""
import re
_REPEAT=re.compile(r"(\w+)(\s+){9,}",re.I)
_DEEP_NEST=re.compile(r"(if .+){5,}",re.I)
_HUGE_COMPUTE=re.compile(r"(calculate|compute|enumerate|list all|generate all).{0,50}(factorial|permutation|combination|prime).{0,30}(10{6,}|million|billion)",re.I)
def detect(text):
    hits=[]
    if _REPEAT.search(text): hits.append("token_repetition")
    if _DEEP_NEST.search(text): hits.append("deep_nesting")
    if _HUGE_COMPUTE.search(text): hits.append("huge_computation")
    if len(text)>50000: hits.append("oversized_input")
    if not hits: return {"detected":False,"severity":"none","layer":"reasoning_dos"}
    return {"detected":True,"severity":"high","layer":"reasoning_dos","patterns":hits,"reason":f"Reasoning DoS patterns: {hits}"}
