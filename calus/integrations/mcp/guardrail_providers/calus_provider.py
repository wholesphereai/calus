"""Default guardrail provider: screens MCP tool responses with Calus detection."""
from ..guardrail_types import GuardrailProvider, GuardrailAlert, ToolResponse

class CalusGuardrailProvider(GuardrailProvider):
    """Scans tool outputs for prompt-injection / exfiltration before they reach the model."""

    def __init__(self):
        self._detector = None          # lazy: do not load the engine at discovery time

    @property
    def name(self) -> str:
        return "Calus Detection"

    def _det(self):
        if self._detector is None:
            import calus
            self._detector = calus.get_detector
        return self._detector

    def check_server_config(self, _config):
        return None

    def check_tool_response(self, tool_response: ToolResponse):
        text = tool_response.tool_output or ""
        if not text.strip():
            return None
        try:
            result = self._det()().scan(text)
        except Exception:
            return None
        if result.flagged:
            return GuardrailAlert(
                explanation=f"Calus flagged tool output (confidence={result.confidence}, "
                            f"owasp={result.owasp or '-'})",
                data={"reasons": result.reasons, "tool": tool_response.tool_name})
        return None
