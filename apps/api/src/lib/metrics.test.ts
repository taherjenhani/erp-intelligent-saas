import assert from "node:assert/strict";
import test from "node:test";

import {
  incrementCounter,
  renderMetrics,
  resetMetricsForTests,
  setGauge,
} from "./metrics";

test("metrics render counters and gauges in prometheus text format", () => {
  resetMetricsForTests();

  incrementCounter(
    "erp_audit_log_write_total",
    "Total audit log writes by action and status.",
    {
      action: "LOGIN_FAILED",
      status: "success",
    }
  );
  setGauge(
    "erp_api_instance_info",
    "API instance identity for per-instance metric scraping.",
    {
      instance: "api-1",
      node_env: "test",
    },
    1
  );
  setGauge(
    "erp_email_outbox_batch_processed",
    "Last email outbox batch processed count.",
    {},
    2
  );

  const output = renderMetrics();

  assert.match(output, /# TYPE erp_audit_log_write_total counter/);
  assert.match(
    output,
    /erp_audit_log_write_total\{action="LOGIN_FAILED",status="success"\} 1/
  );
  assert.match(output, /# TYPE erp_email_outbox_batch_processed gauge/);
  assert.match(output, /erp_email_outbox_batch_processed 2/);
  assert.match(
    output,
    /erp_api_instance_info\{instance="api-1",node_env="test"\} 1/
  );
});
