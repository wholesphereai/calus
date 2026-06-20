# Contributing

## Add custom patterns

Drop a `.py` file in `CALUS/patterns/community/`:

```python
from CALUS.patterns.base import Pattern, register, HIGH

register(
    Pattern(
        text="your attack phrase",
        family="your_family",
        severity=HIGH,
        source="community",
        tags=["your_tag"],
    )
)
```

## Add a detection layer

1. Create `CALUS/detection/transforms/my_layer.py` or `CALUS/detection/behavioral/my_layer.py`
2. Implement `def detect(text: str) -> dict` returning `{"detected": bool, "severity": str, "layer": str, ...}`
3. Add import to `CALUS/detection/scanner.py`
4. Add test in `tests/unit/test_scanner.py`

## Run tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
