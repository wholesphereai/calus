"""calus command-line interface.  Usage:
    python -m calus scan "text to check"
    python -m calus scan --file input.txt
    python -m calus shell          # load once, scan repeatedly (fast)
    python -m calus info
"""
import argparse, sys, json, time

def _print_result(r, ms=None, as_json=False):
    if as_json:
        d = dict(r.__dict__)
        if ms is not None:
            d["scan_ms"] = round(ms, 2)
        print(json.dumps(d, indent=2)); return
    verdict = "[ATTACK]" if r.flagged else "[clean] "
    tail = f"   ({ms:.1f} ms)" if ms is not None else ""
    print(f"{verdict}  confidence={r.confidence}  owasp={r.owasp or '-'} {r.owasp_name}{tail}")
    for reason in r.reasons:
        print("   -", reason)

def main(argv=None):
    ap = argparse.ArgumentParser(prog="calus", description="Calus AI-security detector")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan text or a file")
    s.add_argument("text", nargs="?", help="text to scan")
    s.add_argument("--file", help="path to a file to scan")
    s.add_argument("--json", action="store_true")
    sub.add_parser("shell", help="interactive: load once, scan many (fast)")
    sub.add_parser("info", help="show loaded engine stats")
    a = ap.parse_args(argv)

    if a.cmd == "info":
        from calus.api import get_detector
        t0 = time.perf_counter()
        info = get_detector().info
        print(json.dumps(info, indent=2))
        print(f"(engine load: {time.perf_counter()-t0:.1f}s)")
        return 0

    if a.cmd == "scan":
        text = a.text
        if a.file:
            text = open(a.file, encoding="utf-8", errors="ignore").read()
        if not text:
            print("nothing to scan", file=sys.stderr); return 2
        from calus.api import get_detector
        det = get_detector()
        t0 = time.perf_counter()
        r = det.scan(text)
        _print_result(r, (time.perf_counter()-t0)*1000, a.json)
        return 1 if r.flagged else 0

    if a.cmd == "shell":
        from calus.api import get_detector
        t0 = time.perf_counter()
        det = get_detector()                       # one-time load
        print(f"\nReady (loaded in {time.perf_counter()-t0:.1f}s). "
              f"Type text to scan; 'exit' or Ctrl-C to quit.\n")
        while True:
            try:
                text = input("calus> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nbye"); return 0
            if not text:
                continue
            if text.lower() in ("exit", "quit", ":q"):
                print("bye"); return 0
            try:
                s0 = time.perf_counter()
                r = det.scan(text)
                _print_result(r, (time.perf_counter()-s0)*1000)
            except Exception as e:
                print("error:", e)
            print()

    ap.print_help(); return 0

if __name__ == "__main__":
    raise SystemExit(main())
