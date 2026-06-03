import type { Role } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { writeAuditLog } from "../lib/audit";
import { PermissionError } from "../lib/errors";
import { prisma } from "../lib/prisma";

async function denyAccess(
  request: FastifyRequest,
  metadata: Record<string, unknown>
): Promise<never> {
  await writeAuditLog({
    action: "ACCESS_DENIED",
    userId: request.auth?.userId,
    ipAddress: request.ip,
    userAgent: request.headers["user-agent"],
    metadata: {
      path: request.url,
      ...metadata,
    },
  });

  throw new PermissionError();
}

export function requireRole(roles: Role[]) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    if (!roles.includes(auth.role)) {
      await denyAccess(request, {
        reason: "role_not_allowed",
        requiredRoles: roles,
      });
    }
  };
}

export function requirePermission(permissionKey: string) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const rolePermission = await prisma.rolePermission.findFirst({
      where: {
        role: auth.role,
        permission: {
          key: permissionKey,
        },
      },
      select: {
        id: true,
      },
    });

    if (!rolePermission) {
      await denyAccess(request, {
        reason: "permission_missing",
        permissionKey,
      });
    }
  };
}
