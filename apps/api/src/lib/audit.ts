import type {
  AuditAction,
  Prisma,
  SecurityEventSeverity,
  SecurityEventType,
} from "@prisma/client";

import { incrementCounter } from "./metrics";
import { prisma } from "./prisma";
import { writeSecurityEvent } from "./securityEvents";

type AuditInput = {
  action: AuditAction;
  userId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  correlationId?: string | null;
  metadata?: Prisma.InputJsonValue;
};

function buildAuditMetadata(input: AuditInput) {
  if (!input.correlationId) {
    return input.metadata;
  }

  if (
    typeof input.metadata === "object" &&
    input.metadata !== null &&
    !Array.isArray(input.metadata)
  ) {
    return {
      ...input.metadata,
      correlationId: input.correlationId,
    };
  }

  return {
    correlationId: input.correlationId,
    metadata: input.metadata,
  };
}

function securitySeverityForAction(
  action: AuditAction
): SecurityEventSeverity {
  switch (action) {
    case "TOKEN_REUSE_DETECTED":
      return "HIGH";
    case "ACCESS_DENIED":
    case "PASSWORD_CHANGED":
    case "PASSWORD_RESET_COMPLETED":
      return "MEDIUM";
    case "LOGIN_FAILED":
      return "LOW";
    default:
      return "INFO";
  }
}

export async function writeAuditLog(input: AuditInput) {
  try {
    const metadata = buildAuditMetadata(input);

    await prisma.auditLog.create({
      data: {
        action: input.action,
        userId: input.userId ?? null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        correlationId: input.correlationId ?? null,
        metadata,
      },
    });
    await writeSecurityEvent({
      type: input.action as SecurityEventType,
      severity: securitySeverityForAction(input.action),
      userId: input.userId,
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      correlationId: input.correlationId,
      metadata,
    });
    incrementCounter(
      "erp_audit_log_write_total",
      "Total audit log writes by action and status.",
      {
        action: input.action,
        status: "success",
      }
    );
  } catch (error) {
    incrementCounter(
      "erp_audit_log_write_total",
      "Total audit log writes by action and status.",
      {
        action: input.action,
        status: "failure",
      }
    );
    console.error("Audit log failed", error);
  }
}
