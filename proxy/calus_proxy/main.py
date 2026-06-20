"""
Calus Proxy — an OpenAI-compatible gateway that scans every call with Calus and
logs the verdicts for a dashboard. DETECTION ONLY: it never blocks, alters, or
redacts the live traffic — requests and responses pass through untouched.

    uvicorn calus_proxy.main:app --host 0.0.0.0 --port 8000

Point any OpenAI-compatible app at it:
    base_url = "http://localhost:8000/v1"
LiteLLM handles the upstream call, so `model` can be any provider it supports
(openai/gpt-4o, anthropic/claude-..., gemini/..., ollama/..., groq/..., etc.).
"""
import json
import time
import uuid
import asyncio
from typing import Optional

from fastapi import FastAPI, Request, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

import litellm
import calus

from .config import get_settings
from .store import Store

settings = get_settings()
ADMIN_TOKEN = settings.ensure_admin_token()
store = Store(settings.db_path)

# warm the detector once at startup so the first request isn't slow
_detector_ready = False

app = FastAPI(title="Calus Proxy", version="1.0.0",
              description="OpenAI-compatible LLM proxy with inline Calus detection (observe-only).")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _warm():
    global _detector_ready
    await asyncio.get_event_loop().run_in_executor(None, calus.get_detector)
    _detector_ready = True


# ----------------------------- helpers --------------------------------------
def _content_text(content) -> str:
    """Flatten one message's content (string, or OpenAI multi-part list) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(seg.get("text", "") for seg in content
                         if isinstance(seg, dict) and seg.get("type") == "text")
    return ""


def _text_of(messages) -> str:
    parts = [_content_text(m.get("content")) for m in messages or []]
    return "\n".join(p for p in parts if p)


def _newest_input_text(messages) -> str:
    """The newest input on THIS request — what's actually new, not the whole
    conversation a chat app replays every time. That's the last user turn for a
    normal message, or the tool result on a tool round-trip (where indirect
    injection hides). So each logged call reflects its own prompt and old history
    isn't re-flagged turn after turn."""
    for m in reversed(messages or []):
        if m.get("role") in ("user", "tool"):
            t = _content_text(m.get("content"))
            if t.strip():
                return t
    return _text_of(messages)            # fallback: no distinct user/tool turn


def _provider_of(model: str) -> str:
    if not model:
        return "unknown"
    return model.split("/", 1)[0] if "/" in model else "openai"


def _agent_of(body: dict, request: Request) -> str:
    """Identify the calling agent: explicit header wins, else the OpenAI `user`
    field, else the model name. Lets the dashboard group multi-agent traffic."""
    hdr = request.headers.get("x-calus-agent")
    if hdr:
        return hdr.strip()[:120]
    u = body.get("user")
    if isinstance(u, str) and u.strip():
        return u.strip()[:120]
    return (body.get("model") or "unknown")[:120]


def _tools_of(body: dict) -> list:
    """Names of tools/functions the agent has been given in this request."""
    out = []
    for t in body.get("tools") or []:
        if isinstance(t, dict):
            fn = t.get("function") or {}
            out.append(fn.get("name") or t.get("name") or t.get("type") or "tool")
    # legacy OpenAI `functions` field
    for f in body.get("functions") or []:
        if isinstance(f, dict) and f.get("name"):
            out.append(f["name"])
    return sorted({x for x in out if x})


def _tool_calls_of(message: dict) -> list:
    """Tool calls the model actually requested, with redacted arguments."""
    out = []
    for tc in (message or {}).get("tool_calls") or []:
        fn = tc.get("function") or {} if isinstance(tc, dict) else {}
        name = fn.get("name") or "tool"
        args = fn.get("arguments") or ""
        if settings.redact_stored_text and isinstance(args, str) and args:
            try:
                args = calus.redact(args).text
            except Exception:
                pass
        out.append({"name": name, "arguments": str(args)[:1000]})
    # legacy single function_call
    fc = (message or {}).get("function_call")
    if isinstance(fc, dict) and fc.get("name"):
        a = fc.get("arguments") or ""
        if settings.redact_stored_text and isinstance(a, str) and a:
            try:
                a = calus.redact(a).text
            except Exception:
                pass
        out.append({"name": fc["name"], "arguments": str(a)[:1000]})
    return out


def _scan_and_store(text: str, direction: str, model: str, latency_ms=None,
                    usage=None, trace_id=None, agent=None, tools=None,
                    tool_calls=None) -> dict:
    """Scan text with Calus and persist the verdict. Returns the verdict dict.

    Records the row even when `text` is empty if the turn carried tool calls —
    an agent's tool-call turn often has no message content but is exactly what we
    want to observe."""
    tools = tools or []
    tool_calls = tool_calls or []
    has_payload = bool(text.strip()) or bool(tool_calls) or bool(tools)
    if not has_payload:
        return {}

    if text.strip():
        r = calus.scan(text)
        flagged = bool(r.flagged) and r.confidence >= settings.flag_threshold
        owasp = getattr(r, "owasp", "") or ""
        owasp_name = getattr(r, "owasp_name", "") or ""
        reasons = list(getattr(r, "reasons", []) or [])
        tiers = list(getattr(r, "tiers_run", []) or [])
        confidence = round(float(r.confidence), 3)
    else:
        flagged, owasp, owasp_name, reasons, tiers, confidence = False, "", "", [], [], 0.0

    stored_text, findings = None, []
    if settings.store_text and text.strip():
        if settings.redact_stored_text:
            red = calus.redact(text)
            stored_text = red.text[:2000]
            findings = sorted({k for k, _ in red.findings})
        else:
            stored_text = text[:2000]

    pt = ct = None
    if usage:
        pt = usage.get("prompt_tokens")
        ct = usage.get("completion_tokens")

    rid = store.record(
        ts=time.time(), trace_id=trace_id, agent=agent,
        model=model, provider=_provider_of(model), direction=direction,
        flagged=flagged, confidence=confidence,
        owasp=owasp, owasp_name=owasp_name, reasons=reasons, tiers=tiers,
        tools=tools, tool_calls=tool_calls,
        latency_ms=latency_ms, prompt_tokens=pt, completion_tokens=ct,
        text_redacted=stored_text, findings=findings,
    )
    return {"id": rid, "flagged": flagged, "confidence": confidence, "owasp": owasp}


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


# ----------------------------- proxy route ----------------------------------
@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request, authorization: Optional[str] = Header(None)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    model = body.get("model", "")
    messages = body.get("messages", [])
    stream = bool(body.get("stream"))

    # request-scoped context for the dashboard (agent tracing)
    trace_id = uuid.uuid4().hex
    agent = _agent_of(body, request)
    tools = _tools_of(body)

    # scan the INPUT (never blocks — just records). We use the latest user turn,
    # not the whole replayed history, so each call shows its own prompt.
    _scan_and_store(_newest_input_text(messages), "input", model, trace_id=trace_id,
                    agent=agent, tools=tools)

    # forward upstream via LiteLLM. The provider key is resolved in priority:
    #   1. the caller's bearer (used in-flight, NEVER stored), else
    #   2. a key saved in the encrypted vault for this provider, else
    #   3. whatever LiteLLM finds in the environment.
    api_key = _bearer(authorization)
    if not api_key:
        try:
            api_key = store.key_for_provider(_provider_of(model))
        except Exception:
            api_key = None
    call_kwargs = dict(body)                 # forwarded untouched (detection-only)
    if api_key:
        call_kwargs["api_key"] = api_key

    t0 = time.perf_counter()
    try:
        resp = await litellm.acompletion(**call_kwargs)
    except Exception as e:
        # transparent error passthrough (OpenAI error shape)
        return JSONResponse(status_code=getattr(e, "status_code", 502),
                            content={"error": {"message": str(e)[:500],
                                               "type": type(e).__name__}})

    # ---- streaming ----
    if stream:
        async def gen():
            acc = []
            try:
                async for chunk in resp:
                    d = chunk.model_dump() if hasattr(chunk, "model_dump") else chunk
                    try:
                        acc.append(d["choices"][0]["delta"].get("content") or "")
                    except Exception:
                        pass
                    yield f"data: {json.dumps(d)}\n\n"
            finally:
                yield "data: [DONE]\n\n"
                if settings.scan_responses:
                    dt = (time.perf_counter() - t0) * 1000
                    _scan_and_store("".join(acc), "output", model, latency_ms=dt,
                                    trace_id=trace_id, agent=agent)
        return StreamingResponse(gen(), media_type="text/event-stream")

    # ---- non-streaming ----
    dt = (time.perf_counter() - t0) * 1000
    d = resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)
    if settings.scan_responses:
        try:
            msg = d["choices"][0]["message"]
            out_text = msg.get("content") or ""
        except Exception:
            msg, out_text = {}, ""
        _scan_and_store(out_text, "output", model, latency_ms=dt, usage=d.get("usage"),
                        trace_id=trace_id, agent=agent, tool_calls=_tool_calls_of(msg))
    return JSONResponse(content=d)


# ----------------------------- dashboard API --------------------------------
def require_admin(x_admin_token: Optional[str] = Header(None)):
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="invalid or missing X-Admin-Token")


@app.get("/healthz")
async def healthz():
    return {"ok": True, "detector_ready": _detector_ready}


@app.get("/api/admin-token", dependencies=[Depends(require_admin)])
async def api_admin_token():
    """Echo the current admin token to an already-authenticated client so it can
    be copied for other devices / the proxy config. (You must already hold it.)"""
    return {"token": ADMIN_TOKEN}


@app.get("/api/stats", dependencies=[Depends(require_admin)])
async def api_stats():
    return store.stats()


@app.get("/api/threats", dependencies=[Depends(require_admin)])
async def api_threats():
    return store.threats()


@app.get("/api/timeseries", dependencies=[Depends(require_admin)])
async def api_timeseries(hours: int = 24):
    return store.timeseries(hours=hours)


@app.get("/api/logs", dependencies=[Depends(require_admin)])
async def api_logs(limit: int = Query(50, le=200), offset: int = 0,
                   flagged: Optional[bool] = None, owasp: Optional[str] = None,
                   agent: Optional[str] = None):
    return store.logs(limit=limit, offset=offset, flagged=flagged, owasp=owasp, agent=agent)


@app.get("/api/logs/{rid}", dependencies=[Depends(require_admin)])
async def api_log(rid: str):
    row = store.get(rid)
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return row


@app.get("/api/agents", dependencies=[Depends(require_admin)])
async def api_agents():
    """Per-agent rollup: traffic, flagged count, tools used, models, last seen."""
    return store.agents()


@app.get("/api/trace/{trace_id}", dependencies=[Depends(require_admin)])
async def api_trace(trace_id: str):
    """Full input→output trace of one request (the agent's turn)."""
    rows = store.trace(trace_id)
    if not rows:
        raise HTTPException(status_code=404, detail="not found")
    return rows


# ----------------------------- API key vault --------------------------------
# Provider keys saved here are encrypted at rest (see crypto.py) and only ever
# decrypted in memory to forward a request. The list view returns masked keys;
# the full key is only returned by the explicit /reveal route.
_ENV_KEY_VARS = {
    "OPENAI_API_KEY": "openai", "GROQ_API_KEY": "groq",
    "ANTHROPIC_API_KEY": "anthropic", "GEMINI_API_KEY": "gemini",
    "MISTRAL_API_KEY": "mistral", "COHERE_API_KEY": "cohere",
}


@app.get("/api/keys", dependencies=[Depends(require_admin)])
async def api_keys_list():
    # vault keys (manageable) + provider keys found in the environment (read-only),
    # so a key configured in proxy/.env is still visible in the dashboard.
    import os
    from .crypto import mask
    keys = [{**k, "source": "vault"} for k in store.list_keys()]
    for var, prov in _ENV_KEY_VARS.items():
        v = (os.environ.get(var) or "").strip()
        if v and "REPLACE" not in v.upper():          # skip example placeholders
            keys.append({"id": "env:" + prov, "ts": 0, "provider": prov,
                         "label": f"from {var}", "masked": mask(v), "source": "env"})
    return keys


@app.post("/api/keys", dependencies=[Depends(require_admin)])
async def api_keys_add(request: Request):
    body = await request.json()
    provider = (body.get("provider") or "").strip()
    secret = (body.get("key") or body.get("secret") or "").strip()
    label = (body.get("label") or "").strip()
    if not provider or not secret:
        raise HTTPException(status_code=400, detail="provider and key are required")
    return store.add_key(provider, secret, label)


@app.get("/api/keys/{kid}/reveal", dependencies=[Depends(require_admin)])
async def api_keys_reveal(kid: str):
    if kid.startswith("env:"):
        import os
        prov = kid.split(":", 1)[1]
        var = next((v for v, p in _ENV_KEY_VARS.items() if p == prov), None)
        full = (os.environ.get(var) or "").strip() if var else ""
        if not full:
            raise HTTPException(status_code=404, detail="not found")
        return {"id": kid, "key": full}
    full = store.reveal_key(kid)
    if full is None:
        raise HTTPException(status_code=404, detail="not found")
    return {"id": kid, "key": full}


@app.put("/api/keys/{kid}", dependencies=[Depends(require_admin)])
async def api_keys_update(kid: str, request: Request):
    if kid.startswith("env:"):
        raise HTTPException(status_code=400, detail="env keys are read-only — edit proxy/.env")
    body = await request.json()
    label = body.get("label")
    secret = (body.get("key") or body.get("secret") or "").strip() or None
    if not store.update_key(kid, label=label, secret=secret):
        raise HTTPException(status_code=404, detail="not found")
    return {"updated": kid}


@app.delete("/api/keys/{kid}", dependencies=[Depends(require_admin)])
async def api_keys_delete(kid: str):
    if kid.startswith("env:"):
        raise HTTPException(status_code=400, detail="env keys are read-only — edit proxy/.env")
    if not store.delete_key(kid):
        raise HTTPException(status_code=404, detail="not found")
    return {"deleted": kid}
