"""Community patterns — drop .py files here, each calling register()."""
import importlib, os, logging
log = logging.getLogger(__name__)
_dir = os.path.dirname(__file__)
for _f in os.listdir(_dir):
    if _f.endswith(".py") and _f != "__init__.py":
        try: importlib.import_module(f"calus.patterns.community.{_f[:-3]}")
        except Exception as e: log.warning("community pattern load failed: %s %s", _f, e)
