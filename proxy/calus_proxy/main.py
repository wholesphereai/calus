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
import hmac
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

import litellm
import calus

from .config import get_settings
from .store import Store

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("calus_proxy")

settings = get_settings()
ADMIN_TOKEN = settings.ensure_admin_token()
PROXY_TOKEN = settings.proxy_token
store = Store(settings.db_path)

# warm the detector once at startup so the first request isn't slow
_detector_ready = False

# Keys that select the upstream endpoint — stripping them prevents a caller from
# redirecting the request (and the vault key) to an attacker-controlled host (SSRF
# / key exfiltration). Anything ending in _url/_base is stripped too.
_ENDPOINT_OVERRIDE_KEYS = {"api_base", "base_url", "api_version", "custom_llm_provider"}

# providers we recognise and will attach a vault/env key for
_KNOWN_PROVIDERS = {
    "openai", "anthropic", "gemini", "groq", "mistral", "cohere",
    "azure", "bedrock", "vertex_ai", "ollama", "together_ai", "replicate",
    "perplexity", "deepseek", "xai", "fireworks_ai", "huggingface",
}

# CORS: data-plane auth is a custom header (not cookies), so credentials are off.
# With credentials off, a wildcard origin is acceptable; but if any explicit
# origin is "*" alongside others we drop it to keep the list explicit.
_cors_origins = list(settings.cors_origins)
if "*" in _cors_origins and len(_cors_origins) > 1:
    log.warning("CORS origin '*' mixed with explicit origins — dropping '*'")
    _cors_origins = [o for o in _cors_origins if o != "*"]

@asynccontextmanager
async def _lifespan(app: FastAPI):
    # ---- startup ----
    global _detector_ready
    if not PROXY_TOKEN:
        log.warning("CALUS_PROXY_TOKEN is not set — the data plane (/v1/*) is "
                    "UNAUTHENTICATED. This keeps the proxy drop-in, but the port "
                    "must NOT be publicly exposed. Set CALUS_PROXY_TOKEN to require a token.")
    det = await asyncio.get_event_loop().run_in_executor(None, calus.get_detector)
    _detector_ready = True
    # Log the REAL loaded rule/signature counts from the detector's info (the
    # production build_from_package loader), not the dead register() registry.
    info = getattr(det, "info", {}) or {}
    active = info.get("active_rules", "?")
    sigs = info.get("attack_signatures", "?")
    log.info("Calus engine: %s active rules, %s attack signatures loaded", active, sigs)
    log.info("detector warm; proxy ready")
    yield
    # ---- shutdown (nothing to clean up) ----


app = FastAPI(title="Calus Proxy", version="1.0.0",
              description="OpenAI-compatible LLM proxy with inline Calus detection (observe-only).",
              lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,          # auth is a custom header, never cookies
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Any unhandled error in a route returns a generic body — never a stack
    trace or internal detail (which could leak keys/prompt content)."""
    log.error("unhandled error on %s", request.url.path, exc_info=True)
    return JSONResponse(status_code=500,
                        content={"error": "detection failed", "code": 500})


def _require_proxy_token(request: Request):
    """Constant-time data-plane token check. No-op when CALUS_PROXY_TOKEN unset."""
    if not PROXY_TOKEN:
        return
    presented = request.headers.get("x-calus-proxy-token") or ""
    auth = request.headers.get("authorization") or ""
    if not presented and auth.lower().startswith("bearer "):
        presented = auth.split(" ", 1)[1].strip()
    if not hmac.compare_digest(presented, PROXY_TOKEN):
        raise HTTPException(status_code=401, detail="invalid or missing data-plane token")


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


def _safe_redact(text: str) -> str:
    """Redact `text`, FAILING CLOSED: if redaction raises, mask everything rather
    than risk storing a secret in cleartext."""
    if not settings.redact_stored_text:
        return text
    if not isinstance(text, str) or not text:
        return text
    try:
        return calus.redact(text).text
    except Exception:
        log.warning("redaction failed — masking text to fail closed", exc_info=True)
        return "[REDACTED]"


def _tool_calls_of(message: dict) -> list:
    """Tool calls the model actually requested, with redacted arguments."""
    out = []
    for tc in (message or {}).get("tool_calls") or []:
        fn = tc.get("function") or {} if isinstance(tc, dict) else {}
        name = fn.get("name") or "tool"
        args = fn.get("arguments") or ""
        if isinstance(args, str) and args:
            args = _safe_redact(args)
        out.append({"name": name, "arguments": str(args)[:1000]})
    # legacy single function_call
    fc = (message or {}).get("function_call")
    if isinstance(fc, dict) and fc.get("name"):
        a = fc.get("arguments") or ""
        if isinstance(a, str) and a:
            a = _safe_redact(a)
        out.append({"name": fc["name"], "arguments": str(a)[:1000]})
    return out


async def _scan_and_store(text: str, direction: str, model: str, latency_ms=None,
                          usage=None, trace_id=None, agent=None, tools=None,
                          tool_calls=None) -> dict:
    """Scan text with Calus and persist the verdict. Returns the verdict dict.

    Records the row even when `text` is empty if the turn carried tool calls —
    an agent's tool-call turn often has no message content but is exactly what we
    want to observe. CPU-bound calus calls run off the event loop so requests
    don't block each other."""
    tools = tools or []
    tool_calls = tool_calls or []
    has_payload = bool(text.strip()) or bool(tool_calls) or bool(tools)
    if not has_payload:
        return {}

    if text.strip():
        r = await asyncio.to_thread(calus.scan, text)
        flagged = bool(r.flagged) and r.confidence >= settings.flag_threshold
        owasp = getattr(r, "owasp", "") or ""
        owasp_name = getattr(r, "owasp_name", "") or ""
        reasons = list(getattr(r, "reasons", []) or [])
        # reasons can include the matched snippet of user text — redact it too
        # (fail closed: if redaction errors, mask the whole reason string)
        if settings.redact_stored_text:
            reasons = [await asyncio.to_thread(_safe_redact, x) for x in reasons]
        tiers = list(getattr(r, "tiers_run", []) or [])
        confidence = round(float(r.confidence), 3)
    else:
        flagged, owasp, owasp_name, reasons, tiers, confidence = False, "", "", [], [], 0.0

    stored_text, findings = None, []
    if settings.store_text and text.strip():
        if settings.redact_stored_text:
            try:
                red = await asyncio.to_thread(calus.redact, text)
                stored_text = red.text[:2000]
                findings = sorted({k for k, _ in red.findings})
            except Exception:
                # fail closed — never store the raw text if redaction failed
                log.warning("redaction failed for stored_text — masking", exc_info=True)
                stored_text = "[REDACTED]"
                findings = []
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
    return {"id": rid, "flagged": flagged, "confidence": confidence,
            "owasp": owasp, "reasons": reasons, "tiers": tiers}


def _verdict_headers(verdict: dict) -> dict:
    """Build the x-calus-* response headers from an INPUT scan verdict so callers
    can see the detection result inline. `x-calus-patterns` is a short, comma-
    joined list of matched reasons/rule categories truncated to ~200 chars."""
    if not verdict:
        return {}
    reasons = verdict.get("reasons") or []
    patterns = ", ".join(str(r) for r in reasons)[:200]
    return {
        "x-calus-flagged": "true" if verdict.get("flagged") else "false",
        "x-calus-confidence": str(verdict.get("confidence", 0.0)),
        "x-calus-owasp": str(verdict.get("owasp") or ""),
        "x-calus-patterns": patterns,
    }


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


# ----------------------------- proxy route ----------------------------------
@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request, authorization: Optional[str] = Header(None)):
    _require_proxy_token(request)

    trace_id = uuid.uuid4().hex

    # body-size limit: read raw bytes and reject oversized payloads before parsing
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        raise HTTPException(status_code=413, detail="request body too large")
    try:
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    model = body.get("model", "")
    messages = body.get("messages", [])
    stream = bool(body.get("stream"))

    # request-scoped context for the dashboard (agent tracing)
    agent = _agent_of(body, request)
    tools = _tools_of(body)

    # scan the INPUT (never blocks — just records). We use the latest user turn,
    # not the whole replayed history, so each call shows its own prompt. Capture
    # the verdict so we can surface it on the response via x-calus-* headers.
    input_verdict = await _scan_and_store(_newest_input_text(messages), "input", model,
                                          trace_id=trace_id, agent=agent, tools=tools)
    calus_headers = _verdict_headers(input_verdict)

    # forward upstream via LiteLLM. The provider key is resolved in priority:
    #   1. the caller's bearer (used in-flight, NEVER stored), else
    #   2. a key saved in the encrypted vault for this provider, else
    #   3. whatever LiteLLM finds in the environment.
    provider = _provider_of(model)
    api_key = _bearer(authorization)
    if not api_key and provider in _KNOWN_PROVIDERS:
        try:
            api_key = store.key_for_provider(provider)
        except Exception:
            api_key = None

    # SSRF / key-exfiltration guard: never let the caller redirect the upstream
    # endpoint (which would send our vault key to an attacker's host). Strip every
    # endpoint-override key from the forwarded body.
    call_kwargs = {
        k: v for k, v in body.items()
        if k not in _ENDPOINT_OVERRIDE_KEYS
        and not (isinstance(k, str) and (k.endswith("_url") or k.endswith("_base")))
    }
    call_kwargs["timeout"] = settings.upstream_timeout_s
    # only attach a provider key for a known provider prefix
    if api_key and provider in _KNOWN_PROVIDERS:
        call_kwargs["api_key"] = api_key

    t0 = time.perf_counter()
    try:
        resp = await litellm.acompletion(**call_kwargs)
    except asyncio.TimeoutError:
        log.error("upstream timeout (trace_id=%s)", trace_id)
        return JSONResponse(status_code=504,
                            content={"error": {"message": "upstream request timed out",
                                               "type": "upstream_timeout"}})
    except Exception as e:
        # Don't leak the raw upstream error (may contain keys). Log server-side,
        # return a generic message. Timeout exceptions map to 504.
        name = type(e).__name__.lower()
        if "timeout" in name:
            log.error("upstream timeout (trace_id=%s): %r", trace_id, e)
            return JSONResponse(status_code=504,
                                content={"error": {"message": "upstream request timed out",
                                                   "type": "upstream_timeout"}})
        log.error("upstream request failed (trace_id=%s)", trace_id, exc_info=True)
        return JSONResponse(status_code=getattr(e, "status_code", 502),
                            content={"error": {"message": "upstream request failed",
                                               "type": "upstream_error"}})

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
                    await _scan_and_store("".join(acc), "output", model, latency_ms=dt,
                                          trace_id=trace_id, agent=agent)
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers=calus_headers)

    # ---- non-streaming ----
    dt = (time.perf_counter() - t0) * 1000
    d = resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)
    if settings.scan_responses:
        try:
            msg = d["choices"][0]["message"]
            out_text = msg.get("content") or ""
        except Exception:
            msg, out_text = {}, ""
        await _scan_and_store(out_text, "output", model, latency_ms=dt, usage=d.get("usage"),
                              trace_id=trace_id, agent=agent, tool_calls=_tool_calls_of(msg))
    return JSONResponse(content=d, headers=calus_headers)


# ----------------------------- dashboard API --------------------------------
def require_admin(x_admin_token: Optional[str] = Header(None)):
    # constant-time compare to avoid leaking the token via timing
    if not hmac.compare_digest(x_admin_token or "", ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="invalid or missing X-Admin-Token")


@app.get("/healthz")
async def healthz():
    # readiness gate: 503 until the detector is warm so orchestrators don't route
    # traffic before the engine can scan it
    if not _detector_ready:
        return JSONResponse(status_code=503,
                            content={"ok": False, "detector_ready": False})
    return {"ok": True, "detector_ready": True}


@app.get("/v1/models")
@app.get("/models")
async def list_models(request: Request):
    """Minimal OpenAI-style model list so clients that probe /v1/models don't
    break. Static — the actual model is chosen per-request via `model`."""
    _require_proxy_token(request)
    now = int(time.time())
    data = [{"id": m, "object": "model", "created": now, "owned_by": "calus-proxy"}
            for m in ("gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "gemini-1.5-pro")]
    return {"object": "list", "data": data}


@app.get("/api/admin-token", dependencies=[Depends(require_admin)])
async def api_admin_token():
    """Echo the current admin token to an already-authenticated client so it can
    be copied for other devices / the proxy config. (You must already hold it.)"""
    return {"token": ADMIN_TOKEN, "token_file": str(settings.admin_token_path())}


@app.get("/api/local-auth")
async def api_local_auth(request: Request):
    """Hand the admin token to SAME-MACHINE callers only, so the dashboard can
    auto-authenticate on localhost with no manual entry. Remote callers get 403
    and must paste the token. This is what makes the local demo one-click."""
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=403, detail="local-auth is restricted to localhost")
    return {"token": ADMIN_TOKEN, "token_file": str(settings.admin_token_path())}


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
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
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
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
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
