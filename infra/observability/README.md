# Observability

**Implemented today**
- **Structured logging** (`structlog`): JSON in production, human-readable in dev.
  Key lifecycle, tool, finding, chain, and retest events are logged; secrets are never
  logged (the policy layer keeps secret material out of log events).
- **Audit trail**: every offensive action is persisted as an `AuditEvent`
  (`GET /api/campaigns/{id}/audit`, `GET /api/audit`).
- **Platform metrics**: `GET /api/metrics` returns DB-derived counters — campaigns by
  state, findings by severity, evidence records, total requests, and the fix-verification
  rate.
- **Per-campaign progress + resource accounting**: live phase progress and `requests_made`
  on every campaign.

**Documented production path**
- **OpenTelemetry**: wrap the orchestrator phases and `HttpTool.execute` in spans and
  export via OTLP. Structlog can emit `trace_id`/`span_id` for correlation.
- **Prometheus**: expose counters/histograms (campaigns, tool latency, findings) at a
  `/metrics` scrape endpoint; the existing `/api/metrics` JSON maps directly to gauges.
- **Grafana**: dashboards for campaign throughput, time-to-first-finding, tool latency,
  and fix-verification rate.

These are intentionally additive: the platform is fully observable via structured logs,
the audit trail, and `/api/metrics` without any external collector.
