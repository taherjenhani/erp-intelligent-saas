import type { AuditAction, Prisma } from "@prisma/client";

import { incrementCounter } from "./metrics";
import { prisma } from "./prisma";

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

export async function writeAuditLog(input: AuditInput) {
  try {
    await prisma.auditLog.create({
      data: {
        action: input.action,
        userId: input.userId ?? null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        correlationId: input.correlationId ?? null,
        metadata: buildAuditMetadata(input),
      },
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
