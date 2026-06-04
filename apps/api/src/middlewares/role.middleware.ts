import type { PlatformRole, Role } from "@prisma/client";
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

async function roleHasPermission(role: Role, permissionKey: string) {
  const rolePermission = await prisma.rolePermission.findFirst({
    where: {
      role,
      permission: {
        key: permissionKey,
      },
    },
    select: {
      id: true,
    },
  });

  return Boolean(rolePermission);
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

export function requirePlatformRole(roles: PlatformRole[]) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    if (!roles.includes(auth.platformRole)) {
      await denyAccess(request, {
        reason: "platform_role_not_allowed",
        requiredPlatformRoles: roles,
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

    if (!(await roleHasPermission(auth.role, permissionKey))) {
      await denyAccess(request, {
        reason: "permission_missing",
        permissionKey,
      });
    }
  };
}

export function requireStorePermission(
  storeIdParam: string,
  permissionKey: string
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const storeId =
      (request.params as Record<string, string | undefined>)[
        storeIdParam
      ];

    if (!storeId) {
      return await denyAccess(request, {
        reason: "missing_store_id",
        storeIdParam,
      });
    }

    const role =
      auth.platformRole === "SUPER_ADMIN"
        ? "SUPER_ADMIN"
        : auth.storeRoles[storeId];

    if (!role || !(await roleHasPermission(role, permissionKey))) {
      await denyAccess(request, {
        reason: "store_permission_missing",
        storeId,
        permissionKey,
      });
    }
  };
}

export function requireOrganizationRole(
  organizationIdParam: string,
  roles: Role[]
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const organizationId =
      (request.params as Record<string, string | undefined>)[
        organizationIdParam
      ];

    if (!organizationId) {
      return await denyAccess(request, {
        reason: "missing_organization_id",
        organizationIdParam,
      });
    }

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const organizationRole =
      auth.organizationRoles[organizationId];

    if (!organizationRole || !roles.includes(organizationRole)) {
      await denyAccess(request, {
        reason: "organization_role_not_allowed",
        organizationId,
        requiredRoles: roles,
      });
    }
  };
}

export function requireOrganizationPermission(
  organizationIdParam: string,
  permissionKey: string
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const organizationId =
      (request.params as Record<string, string | undefined>)[
        organizationIdParam
      ];

    if (!organizationId) {
      return await denyAccess(request, {
        reason: "missing_organization_id",
        organizationIdParam,
      });
    }

    const role =
      auth.platformRole === "SUPER_ADMIN"
        ? "SUPER_ADMIN"
        : auth.organizationRoles[organizationId];

    if (!role || !(await roleHasPermission(role, permissionKey))) {
      await denyAccess(request, {
        reason: "organization_permission_missing",
        organizationId,
        permissionKey,
      });
    }
  };
}

export function requireStoreRole(
  storeIdParam: string,
  roles: Role[]
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const storeId =
      (request.params as Record<string, string | undefined>)[
        storeIdParam
      ];

    if (!storeId) {
      return await denyAccess(request, {
        reason: "missing_store_id",
        storeIdParam,
      });
    }

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const storeRole = auth.storeRoles[storeId];

    if (!storeRole || !roles.includes(storeRole)) {
      await denyAccess(request, {
        reason: "store_role_not_allowed",
        storeId,
        requiredRoles: roles,
      });
    }
  };
}

export function requireStoreInOrganization(
  storeIdParam: string,
  organizationIdParam: string
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(request, { reason: "missing_auth" });
    }

    const params = request.params as Record<string, string | undefined>;
    const storeId = params[storeIdParam];
    const organizationId = params[organizationIdParam];

    if (!storeId || !organizationId) {
      return await denyAccess(request, {
        reason: "missing_store_or_organization_id",
        storeIdParam,
        organizationIdParam,
      });
    }

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const store = await prisma.store.findFirst({
      where: {
        id: storeId,
        organizationId,
      },
      select: {
        id: true,
      },
    });

    if (!store) {
      await denyAccess(request, {
        reason: "store_not_in_organization",
        storeId,
        organizationId,
      });
    }
  };
}
