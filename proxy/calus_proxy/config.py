"""Configuration for the Calus proxy. All secrets come from the environment —
nothing sensitive is hardcoded or written to disk in plaintext."""
import os
from functools import lru_cache

# Load a .env file (proxy/.env) if present so CALUS_* and provider keys take
# effect without exporting them by hand. Must run before Settings reads getenv.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


class Settings:
    # --- security ---
    # token the dashboard/API must present (X-Admin-Token). Generated if unset.
    admin_token: str = os.getenv("CALUS_ADMIN_TOKEN", "")
    # comma-separated allowed CORS origins for the dashboard (locked down by default)
    cors_origins: list = [
        o.strip() for o in os.getenv("CALUS_CORS_ORIGINS", "http://localhost:5173").split(",") if o.strip()
    ]
    # redact secrets/PII before anything is written to the log store (recommended ON)
    redact_stored_text: bool = os.getenv("CALUS_REDACT_STORE", "1") not in ("0", "false", "False")
    # store full prompt/response text at all (off -> only metadata + verdict is kept)
    store_text: bool = os.getenv("CALUS_STORE_TEXT", "1") not in ("0", "false", "False")

    # --- storage ---
    db_path: str = os.getenv("CALUS_DB_PATH", "calus_proxy.db")

    # --- proxy behaviour (detection only; never blocks) ---
    scan_responses: bool = os.getenv("CALUS_SCAN_RESPONSES", "1") not in ("0", "false", "False")
    # confidence at/above which a call is recorded as "flagged" in the dashboard
    flag_threshold: float = float(os.getenv("CALUS_FLAG_THRESHOLD", "0.5"))

    # --- upstream provider keys ---
    # These live in the environment only (e.g. OPENAI_API_KEY, ANTHROPIC_API_KEY,
    # GEMINI_API_KEY...). LiteLLM reads them directly. They are NEVER stored or logged.

    def ensure_admin_token(self) -> str:
        if not self.admin_token:
            import secrets
            self.admin_token = secrets.token_urlsafe(24)
            print(f"[calus-proxy] No CALUS_ADMIN_TOKEN set — generated one for this run:\n"
                  f"             {self.admin_token}\n"
                  f"             Set CALUS_ADMIN_TOKEN to keep it stable across restarts.")
        return self.admin_token


@lru_cache
def get_settings() -> Settings:
    return Settings()
