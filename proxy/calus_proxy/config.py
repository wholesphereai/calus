"""Configuration for the Calus proxy. All secrets come from the environment —
nothing sensitive is hardcoded or written to disk in plaintext."""
import os
import logging
from functools import lru_cache

log = logging.getLogger("calus_proxy.config")

# Load a .env file (proxy/.env) if present so CALUS_* and provider keys take
# effect without exporting them by hand. Must run before Settings reads getenv.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def _env_float(name: str, default: float, lo: float = None, hi: float = None) -> float:
    """Parse a float env var, falling back to `default` on bad input and clamping
    to [lo, hi] when given. Never raises — a typo must not crash the proxy."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = float(raw.strip())
    except (TypeError, ValueError):
        log.warning("Invalid %s=%r — not a number; using default %s", name, raw, default)
        return default
    if lo is not None and v < lo:
        log.warning("%s=%s below minimum %s; clamping", name, v, lo)
        v = lo
    if hi is not None and v > hi:
        log.warning("%s=%s above maximum %s; clamping", name, v, hi)
        v = hi
    return v


def _env_int(name: str, default: int, lo: int = None, hi: int = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        v = int(raw.strip())
    except (TypeError, ValueError):
        log.warning("Invalid %s=%r — not an integer; using default %s", name, raw, default)
        return default
    if lo is not None and v < lo:
        log.warning("%s=%s below minimum %s; clamping", name, v, lo)
        v = lo
    if hi is not None and v > hi:
        log.warning("%s=%s above maximum %s; clamping", name, v, hi)
        v = hi
    return v


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


class Settings:
    # --- security ---
    # token the dashboard/API must present (X-Admin-Token). Generated if unset.
    admin_token: str = os.getenv("CALUS_ADMIN_TOKEN", "")
    # OPTIONAL data-plane token; if set, /v1/* requires it (constant-time). Unset
    # keeps the proxy a drop-in (unauthenticated data plane) — must not be exposed.
    proxy_token: str = os.getenv("CALUS_PROXY_TOKEN", "")
    # comma-separated allowed CORS origins for the dashboard (locked down by default)
    cors_origins: list = [
        o.strip() for o in os.getenv("CALUS_CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()
    ]
    # redact secrets/PII before anything is written to the log store (recommended ON)
    redact_stored_text: bool = _env_bool("CALUS_REDACT_STORE", True)
    # store full prompt/response text at all (off -> only metadata + verdict is kept)
    store_text: bool = _env_bool("CALUS_STORE_TEXT", True)

    # --- storage ---
    db_path: str = os.getenv("CALUS_DB_PATH", "calus_proxy.db")

    # --- proxy behaviour ---
    scan_responses: bool = _env_bool("CALUS_SCAN_RESPONSES", True)
    # confidence at/above which a call is recorded as "flagged" in the dashboard
    flag_threshold: float = _env_float("CALUS_FLAG_THRESHOLD", 0.5, lo=0.0, hi=1.0)
    # Enforcement mode for the layered decision-maker:
    #   "verdict"  (DEFAULT) -> detection-only: return the decision in x-calus-*
    #              headers, never stop the request. Keeps Calus a drop-in observer.
    #   "gateway"  (opt-in)  -> gateway-block: a BLOCK decision stops the request
    #              (403 on input, or replaces a forbidden tool-call response).
    # Only "gateway"/"gateway-block"/"block" enable blocking; anything else is verdict.
    enforce_mode: str = (os.getenv("CALUS_ENFORCE_MODE", "verdict") or "verdict").strip().lower()

    @property
    def gateway_block(self) -> bool:
        return self.enforce_mode in ("gateway", "gateway-block", "block")
    # reject request bodies larger than this many bytes (defense against memory abuse)
    max_body_bytes: int = _env_int("CALUS_MAX_BODY_BYTES", 2_000_000, lo=1024)
    # upstream LLM call timeout in seconds
    upstream_timeout_s: float = _env_float("CALUS_UPSTREAM_TIMEOUT_S", 60.0, lo=1.0)

    # --- upstream provider keys ---
    # These live in the environment only (e.g. OPENAI_API_KEY, ANTHROPIC_API_KEY,
    # GEMINI_API_KEY...). LiteLLM reads them directly. They are NEVER stored or logged.

    def config_dir(self) -> str:
        """Directory holding proxy-local secrets (admin token, vault secret)."""
        return os.path.dirname(os.path.abspath(self.db_path)) or "."

    def _token_path(self) -> str:
        return os.path.join(self.config_dir(), ".calus_admin_token")

    def admin_token_path(self) -> str:
        """Public path to the persisted admin token file (shown in the dashboard
        so a user who forgets the token can recover it)."""
        return self._token_path()

    def ensure_admin_token(self) -> str:
        # an explicit env token always wins
        if self.admin_token:
            return self.admin_token
        # otherwise reuse a previously generated token so it stays STABLE across
        # restarts (no need to re-paste it into the dashboard every time)
        path = self._token_path()
        try:
            if os.path.exists(path):
                tok = open(path, encoding="utf-8").read().strip()
                if tok:
                    self.admin_token = tok
                    return tok
        except Exception:
            pass
        # first run with no token set — generate one and persist it
        import secrets
        self.admin_token = secrets.token_urlsafe(24)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.admin_token)
            try:
                os.chmod(path, 0o600)        # owner-only where supported
            except Exception:
                pass
        except Exception:
            pass
        # logged ONCE on first generation only (the file existed branch returns above)
        log.warning(
            "No CALUS_ADMIN_TOKEN set — generated one and saved it to\n"
            "             %s\n"
            "             token: %s\n"
            "             STORE THIS SECURELY. It stays the same across restarts.\n"
            "             Set CALUS_ADMIN_TOKEN to override.",
            path, self.admin_token)
        return self.admin_token


@lru_cache
def get_settings() -> Settings:
    return Settings()
