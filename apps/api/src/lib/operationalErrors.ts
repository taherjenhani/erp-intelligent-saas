import os from "os";

import { env } from "../config/env";
import { incrementCounter } from "./metrics";

type OperationalErrorContext = Record<
  string,
  string | number | boolean | null | undefined
>;

type OperationalEventPayload = {
  level: "error";
  event: string;
  service: string;
  environment: string;
  instance: string;
  resourceAttributes: Record<string, string>;
  context: Record<string, string | number | boolean | null>;
  error: ReturnType<typeof serializeError>;
  occurredAt: string;
};

function serializeError(error: unknown) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }

  return {
    message: "Unknown error",
    value: String(error),
  };
}

function sanitizeContext(context: OperationalErrorContext = {}) {
  return Object.fromEntries(
    Object.entries(context).filter(
      ([, value]) => value !== undefined
    )
  ) as Record<string, string | number | boolean | null>;
}

function parseResourceAttributes(value: string | undefined) {
  if (!value) {
    return {};
  }

  return Object.fromEntries(
    value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean)
      .map((entry) => {
        const separator = entry.indexOf("=");

        if (separator === -1) {
          return [entry, ""];
        }

        return [
          entry.slice(0, separator).trim(),
          entry.slice(separator + 1).trim(),
        ];
      })
      .filter(([key]) => key.length > 0)
  );
}

function buildOperationalPayload(
  event: string,
  error: unknown,
  context: OperationalErrorContext
): OperationalEventPayload {
  return {
    level: "error",
    event,
    service: env.OTEL_SERVICE_NAME,
    environment:
      env.OTEL_DEPLOYMENT_ENVIRONMENT ?? env.NODE_ENV,
    instance:
      env.METRICS_INSTANCE_ID ?? process.env.HOSTNAME ?? os.hostname(),
    resourceAttributes: parseResourceAttributes(
      env.OTEL_RESOURCE_ATTRIBUTES
    ),
    context: sanitizeContext(context),
    error: serializeError(error),
    occurredAt: new Date().toISOString(),
  };
}

async function publishOperationalPayload(payload: OperationalEventPayload) {
  if (!env.OPERATIONAL_EVENTS_WEBHOOK_URL) {
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, env.OPERATIONAL_EVENTS_TIMEOUT_MS);

  try {
    const response = await fetch(env.OPERATIONAL_EVENTS_WEBHOOK_URL, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        ...(env.OPERATIONAL_EVENTS_WEBHOOK_TOKEN
          ? {
              authorization: `Bearer ${env.OPERATIONAL_EVENTS_WEBHOOK_TOKEN}`,
            }
          : {}),
      },
      body: JSON.stringify(payload),
    });

    incrementCounter(
      "erp_operational_event_export_total",
      "Total operational event exports by status.",
      { status: response.ok ? "success" : "failure" }
    );

    if (!response.ok) {
      console.error(
        JSON.stringify({
          level: "error",
          event: "operational_event_export_failed",
          statusCode: response.status,
          originalEvent: payload.event,
        })
      );
    }
  } catch (exportError) {
    incrementCounter(
      "erp_operational_event_export_total",
      "Total operational event exports by status.",
      { status: "failure" }
    );
    console.error(
      JSON.stringify({
        level: "error",
        event: "operational_event_export_failed",
        originalEvent: payload.event,
        error: serializeError(exportError),
      })
    );
  } finally {
    clearTimeout(timeout);
  }
}

export function reportOperationalError(
  event: string,
  error: unknown,
  context: OperationalErrorContext = {}
) {
  const payload = buildOperationalPayload(event, error, context);

  console.error(
    JSON.stringify({
      ...payload,
      ...payload.context,
    })
  );

  void publishOperationalPayload(payload);
}
