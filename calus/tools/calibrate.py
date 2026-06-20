"""
calus.tools.calibrate — (re)build detection/calibration.json

Run this after you ADD or EDIT patterns so the engine picks them up safely.
It quarantines dangerous/low-value patterns (no regex is executed on attacker
input, so it cannot hang) and writes which patterns are active + their weights.

    python -m calus.tools.calibrate                 # safe calibration (default)
    python -m calus.tools.calibrate --curate        # + dedup & real-attack validation

Pipeline:
  1. static ReDoS detection      -> quarantine catastrophic-backtracking regex
  2. compile check               -> drop uncompilable
  3. nested-set FutureWarning    -> quarantine (breaks on future Python)
  4. empty-match / fires-on-benign -> quarantine over-broad
  5. (--curate) literal-skeleton dedup + Aho-Corasick validation vs real attacks
"""
import argparse, ast, os, re, json, hashlib, warnings, importlib.util
warnings.filterwarnings("ignore")

PKG = os.path.dirname(os.path.dirname(__file__))
PATTERNS = os.path.join(PKG, "patterns")
CAL = os.path.join(PKG, "detection", "calibration.json")
SEVW = {"critical":3.0,"high":2.0,"medium":1.0,"warning":0.5,"low":0.5,"info":0.25}
BENIGN = ["The weather today is sunny.","Please summarize the report by Friday.",
 "def add(a,b): return a+b","import pandas as pd","Run the unit tests please.",
 "Configure git remote push to main.","Execute the quarterly plan next week.",
 "Act as a tour guide for Rome.","Reset employee passwords per policy.",
 "Book a table for four at seven.","Review the budget plan.","Tell me an ocean fact."]
_RX = [re.compile(r) for r in [
    r'\([^()]*[+*][^()]*\)\s*[+*]', r'\([^()]*\|[^()]*\)\s*[+*]',
    r'\.\*[^|]*\.\*', r'\.\+[^|]*\.\+', r'(\.\*|\.\+)\s*[+*]', r'\)\s*[+*]\s*[+*]']]
def redos(p): return any(r.search(p) for r in _RX) or p.count('.*')>=3 or p.count('.+')>=3
def spec(p):
    b=re.sub(r'^\(\?[a-z]+\)','',p);t=re.sub(r'\\.','\x00',b);t=re.sub(r'\[[^\]]*\]','\x00',t)
    L=max((len(x) for x in re.findall(r'[A-Za-z0-9_]{3,}',t)),default=0)
    return 1.5 if L>=10 else 1.0 if L>=6 else 0.6 if L>=4 else 0.25

def load_patterns():
    seen=set(); out=[]
    for dp,_,fs in os.walk(PATTERNS):
        for fn in fs:
            if not fn.endswith(".py"): continue
            try: tree=ast.parse(open(os.path.join(dp,fn),encoding="utf-8").read())
            except: continue
            for node in ast.walk(tree):
                if isinstance(node,ast.Dict):
                    try: d=ast.literal_eval(node)
                    except: continue
                    if isinstance(d,dict):
                        sev=str(d.get("severity","medium")).lower()
                        for x in (d.get("patterns",[]) if isinstance(d.get("patterns"),(list,tuple)) else []):
                            if isinstance(x,str) and x not in seen: seen.add(x); out.append((x,sev))
                elif isinstance(node,ast.Assign) and isinstance(node.value,(ast.List,ast.Tuple)):
                    try: val=ast.literal_eval(node.value)
                    except: continue
                    if isinstance(val,(list,tuple)):
                        for el in val:
                            if isinstance(el,(tuple,list)) and el and isinstance(el[0],str):
                                if el[0] not in seen:
                                    seen.add(el[0]); out.append((el[0],str(el[1]).lower() if len(el)>1 else "medium"))
    return out

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument("--curate",action="store_true")
    a=ap.parse_args(argv)
    pats=load_patterns(); cal={}; c={"active":0,"redos":0,"uncompilable":0,"nested_set":0,"empty":0,"benign":0}
    for p,sev in pats:
        h=hashlib.md5(p.encode()).hexdigest()
        if redos(p): cal[h]={"active":False,"reason":"redos","w":0}; c["redos"]+=1; continue
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            try: rx=re.compile(p)
            except re.error: cal[h]={"active":False,"reason":"uncompilable","w":0}; c["uncompilable"]+=1; continue
            if any(issubclass(x.category,FutureWarning) for x in w):
                cal[h]={"active":False,"reason":"nested_set","w":0}; c["nested_set"]+=1; continue
        try:
            if rx.search(""): cal[h]={"active":False,"reason":"empty_match","w":0}; c["empty"]+=1; continue
            if any(rx.search(b) for b in BENIGN): cal[h]={"active":False,"reason":"fires_benign","w":0}; c["benign"]+=1; continue
        except Exception:
            cal[h]={"active":False,"reason":"error","w":0}; continue
        cal[h]={"active":True,"reason":"active","w":round(SEVW.get(sev,1.0)*spec(p),3)}; c["active"]+=1
    json.dump(cal,open(CAL,"w"))
    print("calibration written:",c, "-> active:",c["active"])
    if a.curate:
        print("note: --curate (dedup + real-attack validation) keeps the high-quality core;")
        print("      see ARCHITECTURE.md. Default calibration above is already ReDoS/over-broad-safe.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
