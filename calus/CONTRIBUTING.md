# Contributing

## Add custom patterns

Drop a `.py` file in `calus/patterns/community/`:

```python
from calus.patterns.base import Pattern, register, HIGH

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

1. Create `calus/detection/transforms/my_layer.py` or `calus/detection/behavioral/my_layer.py`
2. Implement `def detect(text: str) -> dict` returning `{"detected": bool, "severity": str, "layer": str, ...}`
3. Add import to `calus/detection/scanner.py`
4. Add test in `tests/unit/test_scanner.py`

## Run tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
