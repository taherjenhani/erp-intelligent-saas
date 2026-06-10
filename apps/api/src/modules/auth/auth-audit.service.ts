import type { AuditAction, Prisma } from "@prisma/client";

import { writeAuditLog } from "../../lib/audit";
import type { AuthContextInput } from "./auth.types";

export async function writeAuthAudit(
  action: AuditAction,
  context: AuthContextInput,
  userId?: string | null,
  metadata?: Prisma.InputJsonObject
) {
  await writeAuditLog({
    action,
    userId,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    correlationId: context.correlationId,
    metadata,
  });
}
