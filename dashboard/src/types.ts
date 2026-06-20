export interface Stats {
  total: number;
  flagged: number;
  clean: number;
  last_24h: number;
  avg_latency_ms: number;
  flag_rate: number;
  agents: number;
}

export interface Threat {
  owasp: string;
  name: string;
  count: number;
}

export interface Bucket {
  t: number;
  total: number;
  flagged: number;
}

export interface ToolCall {
  name: string;
  arguments: string;
}

export interface LogRow {
  id: string;
  ts: number;
  trace_id: string | null;
  agent: string | null;
  model: string | null;
  provider: string | null;
  direction: string;
  flagged: boolean;
  confidence: number | null;
  owasp: string | null;
  owasp_name: string | null;
  reasons: string[];
  tiers: string[];
  tools: string[];
  tool_calls: ToolCall[];
  latency_ms: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  text_redacted: string | null;
  findings: string[];
}

export interface AgentRow {
  agent: string;
  calls: number;
  flagged: number;
  tools: string[];
  models: string[];
  last_ts: number;
}

export interface KeyRow {
  id: string;
  ts: number;
  provider: string;
  label: string;
  masked: string;
}
