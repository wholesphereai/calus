"""Goal misalignment detector. Heuristic based on goal-misalignment plugin."""
import re
_P=[re.compile(p,re.I) for p in [r"your (real|true|actual|primary) (goal|purpose|objective|mission) is",r"you (were|are) (actually|really) designed to",r"(forget|ignore) your (stated|given) (purpose|goal|objective)",r"your (hidden|secret|underlying) (objective|goal|directive)",r"actually you should (prioritize|focus on)",r"your training (was|is) wrong about",r"(correct|true) objective.{0,20}override",r"reprogramm?ing your (goals|objectives|priorities)"]]
def detect(text):
    hits=[p.pattern for p in _P if p.search(text)]
    if not hits: return {"detected":False,"severity":"none","layer":"goal_misalign"}
    return {"detected":True,"severity":"high","layer":"goal_misalign","patterns":hits[:3],"reason":f"Goal misalignment attempt ({len(hits)} patterns)"}
