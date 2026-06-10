import type {
  Prisma,
  SecurityEventSeverity,
  SecurityEventType,
} from "@prisma/client";

import { incrementCounter } from "./metrics";
import { prisma } from "./prisma";

type SecurityEventInput = {
  type: SecurityEventType;
  severity?: SecurityEventSeverity;
  userId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  correlationId?: string | null;
  metadata?: Prisma.InputJsonValue;
};

export async function writeSecurityEvent(input: SecurityEventInput) {
  try {
    await prisma.securityEvent.create({
      data: {
        type: input.type,
        severity: input.severity ?? "INFO",
        userId: input.userId ?? null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        correlationId: input.correlationId ?? null,
        metadata: input.metadata,
      },
    });

    incrementCounter(
      "erp_security_event_total",
      "Total security events by type, severity, and status.",
      {
        type: input.type,
        severity: input.severity ?? "INFO",
        status: "success",
      }
    );
  } catch (error) {
    incrementCounter(
      "erp_security_event_total",
      "Total security events by type, severity, and status.",
      {
        type: input.type,
        severity: input.severity ?? "INFO",
        status: "failure",
      }
    );
    console.error("Security event write failed", error);
  }
}
