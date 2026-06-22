"""Manage the encrypted provider-key vault from the command line.

    python -m calus_proxy.keys add --provider groq --key gsk_... --label prod
    python -m calus_proxy.keys list
    python -m calus_proxy.keys delete <id>

This is the same vault the dashboard's "API keys" page uses: keys are encrypted at
rest and only decrypted in memory to forward a request. Run it from the `proxy/`
directory (or set CALUS_DB_PATH) so it points at the same database the proxy uses.
"""
import argparse
import logging

from .config import get_settings
from .store import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger(__name__)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="calus_proxy.keys",
                                 description="Calus encrypted provider-key vault")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="save a provider key")
    a.add_argument("--provider", required=True, help="openai | groq | anthropic | …")
    a.add_argument("--key", required=True, help="the provider API key")
    a.add_argument("--label", default="", help="optional human label")

    sub.add_parser("list", help="list saved keys (masked)")

    d = sub.add_parser("delete", help="delete a saved key by id")
    d.add_argument("id")

    args = ap.parse_args(argv)
    store = Store(get_settings().db_path)

    if args.cmd == "add":
        rec = store.add_key(args.provider, args.key, args.label)
        log.info("added %s key %s  (id %s)", rec['provider'], rec['masked'], rec['id'])
    elif args.cmd == "list":
        rows = store.list_keys()
        if not rows:
            log.info("(no keys saved)")
        for r in rows:
            log.info("  %s  %-10s %-14s %s", r['id'], r['provider'], r['masked'], r['label'])
    elif args.cmd == "delete":
        log.info("deleted" if store.delete_key(args.id) else "not found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
