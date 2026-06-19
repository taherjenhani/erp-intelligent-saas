import type { PlatformRole, Role } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { writeAuditLog } from "../lib/audit";
import { PermissionError, ValidationError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { requireAuth } from "./auth.middleware";

type DeniedAuditWriter = typeof writeAuditLog;

export type RoleAccess = {
  roleHasPermission(role: Role, permissionKey: string): Promise<boolean>;
  activeOrganizationExists(organizationId: string): Promise<boolean>;
  activeStoreExists(storeId: string): Promise<boolean>;
  storeBelongsToOrganization(
    storeId: string,
    organizationId: string
  ): Promise<boolean>;
};

export type RoleGuardOptions = {
  access?: Partial<RoleAccess>;
  writeDeniedAudit?: DeniedAuditWriter;
};

async function denyAccess(
  request: FastifyRequest,
  metadata: Record<string, unknown>,
  writeDeniedAudit: DeniedAuditWriter = writeAuditLog
): Promise<never> {
  await writeDeniedAudit({
    action: "ACCESS_DENIED",
    userId: request.auth?.userId,
    ipAddress: request.ip,
    userAgent: request.headers["user-agent"],
    correlationId: request.correlationId,
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

async function activeOrganizationExists(organizationId: string) {
  const organization = await prisma.organization.findFirst({
    where: {
      id: organizationId,
      isActive: true,
    },
    select: {
      id: true,
    },
  });

  return Boolean(organization);
}

async function activeStoreExists(storeId: string) {
  const store = await prisma.store.findFirst({
    where: {
      id: storeId,
      isActive: true,
      organization: {
        isActive: true,
      },
    },
    select: {
      id: true,
    },
  });

  return Boolean(store);
}

async function storeBelongsToOrganization(
  storeId: string,
  organizationId: string
) {
  const store = await prisma.store.findFirst({
    where: {
      id: storeId,
      organizationId,
      isActive: true,
      organization: {
        isActive: true,
      },
    },
    select: {
      id: true,
    },
  });

  return Boolean(store);
}

const defaultRoleAccess: RoleAccess = {
  roleHasPermission,
  activeOrganizationExists,
  activeStoreExists,
  storeBelongsToOrganization,
};

function roleAccess(options: RoleGuardOptions): RoleAccess {
  return {
    ...defaultRoleAccess,
    ...options.access,
  };
}

export function requireRole(
  roles: Role[],
  options: RoleGuardOptions = {}
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    if (!roles.includes(auth.role)) {
      await denyAccess(
        request,
        {
          reason: "role_not_allowed",
          requiredRoles: roles,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requirePlatformRole(
  roles: PlatformRole[],
  options: RoleGuardOptions = {}
) {
  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    if (!roles.includes(auth.platformRole)) {
      await denyAccess(
        request,
        {
          reason: "platform_role_not_allowed",
          requiredPlatformRoles: roles,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requirePermission(
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    if (!(await access.roleHasPermission(auth.role, permissionKey))) {
      await denyAccess(
        request,
        {
          reason: "permission_missing",
          permissionKey,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requireStorePermission(
  storeIdParam: string,
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    const storeId =
      (request.params as Record<string, string | undefined>)[
        storeIdParam
      ];

    if (!storeId) {
      return await denyAccess(
        request,
        {
          reason: "missing_store_id",
          storeIdParam,
        },
        options.writeDeniedAudit
      );
    }

    if (!(await access.activeStoreExists(storeId))) {
      return await denyAccess(
        request,
        {
          reason: "store_inactive_or_missing",
          storeId,
        },
        options.writeDeniedAudit
      );
    }

    const role =
      auth.platformRole === "SUPER_ADMIN"
        ? "SUPER_ADMIN"
        : auth.storeRoles[storeId];

    if (!role || !(await access.roleHasPermission(role, permissionKey))) {
      await denyAccess(
        request,
        {
          reason: "store_permission_missing",
          storeId,
          permissionKey,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requireOrganizationRole(
  organizationIdParam: string,
  roles: Role[],
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    const organizationId =
      (request.params as Record<string, string | undefined>)[
        organizationIdParam
      ];

    if (!organizationId) {
      return await denyAccess(
        request,
        {
          reason: "missing_organization_id",
          organizationIdParam,
        },
        options.writeDeniedAudit
      );
    }

    if (!(await access.activeOrganizationExists(organizationId))) {
      return await denyAccess(
        request,
        {
          reason: "organization_inactive_or_missing",
          organizationId,
        },
        options.writeDeniedAudit
      );
    }

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const organizationRole =
      auth.organizationRoles[organizationId];

    if (!organizationRole || !roles.includes(organizationRole)) {
      await denyAccess(
        request,
        {
          reason: "organization_role_not_allowed",
          organizationId,
          requiredRoles: roles,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requireOrganizationPermission(
  organizationIdParam: string,
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    const organizationId =
      (request.params as Record<string, string | undefined>)[
        organizationIdParam
      ];

    if (!organizationId) {
      return await denyAccess(
        request,
        {
          reason: "missing_organization_id",
          organizationIdParam,
        },
        options.writeDeniedAudit
      );
    }

    if (!(await access.activeOrganizationExists(organizationId))) {
      return await denyAccess(
        request,
        {
          reason: "organization_inactive_or_missing",
          organizationId,
        },
        options.writeDeniedAudit
      );
    }

    const role =
      auth.platformRole === "SUPER_ADMIN"
        ? "SUPER_ADMIN"
        : auth.organizationRoles[organizationId];

    if (!role || !(await access.roleHasPermission(role, permissionKey))) {
      await denyAccess(
        request,
        {
          reason: "organization_permission_missing",
          organizationId,
          permissionKey,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requireStoreRole(
  storeIdParam: string,
  roles: Role[],
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    const storeId =
      (request.params as Record<string, string | undefined>)[
        storeIdParam
      ];

    if (!storeId) {
      return await denyAccess(
        request,
        {
          reason: "missing_store_id",
          storeIdParam,
        },
        options.writeDeniedAudit
      );
    }

    if (!(await access.activeStoreExists(storeId))) {
      return await denyAccess(
        request,
        {
          reason: "store_inactive_or_missing",
          storeId,
        },
        options.writeDeniedAudit
      );
    }

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const storeRole = auth.storeRoles[storeId];

    if (!storeRole || !roles.includes(storeRole)) {
      await denyAccess(
        request,
        {
          reason: "store_role_not_allowed",
          storeId,
          requiredRoles: roles,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function requireStoreInOrganization(
  storeIdParam: string,
  organizationIdParam: string,
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);
  const assertCoherentStore =
    assertStoreBelongsToOrganization(
      storeIdParam,
      organizationIdParam,
      options
    );

  return async function (
    request: FastifyRequest,
    reply: FastifyReply
  ) {
    const auth = request.auth;

    if (!auth) {
      return await denyAccess(
        request,
        { reason: "missing_auth" },
        options.writeDeniedAudit
      );
    }

    await assertCoherentStore(request, reply);

    if (auth.platformRole === "SUPER_ADMIN") {
      return;
    }

    const params = request.params as Record<string, string | undefined>;
    const storeId = params[storeIdParam] as string;
    const organizationId = params[organizationIdParam] as string;

    if (!(await access.storeBelongsToOrganization(storeId, organizationId))) {
      await denyAccess(
        request,
        {
          reason: "store_not_in_organization",
          storeId,
          organizationId,
        },
        options.writeDeniedAudit
      );
    }
  };
}

export function assertStoreBelongsToOrganization(
  storeIdParam: string,
  organizationIdParam: string,
  options: RoleGuardOptions = {}
) {
  const access = roleAccess(options);

  return async function (
    request: FastifyRequest,
    _reply: FastifyReply
  ) {
    const params = request.params as Record<string, string | undefined>;
    const storeId = params[storeIdParam];
    const organizationId = params[organizationIdParam];

    if (!storeId || !organizationId) {
      throw new ValidationError(
        "Store and organization identifiers are required"
      );
    }

    if (!(await access.storeBelongsToOrganization(storeId, organizationId))) {
      throw new ValidationError(
        "Store does not belong to the requested organization"
      );
    }
  };
}

export function withOrgAccess(
  organizationIdParam: string,
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  return [
    requireAuth,
    requireOrganizationPermission(
      organizationIdParam,
      permissionKey,
      options
    ),
  ];
}

export function withStoreAccess(
  storeIdParam: string,
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  return [
    requireAuth,
    requireStorePermission(storeIdParam, permissionKey, options),
  ];
}

export function withStoreOrgAccess(
  storeIdParam: string,
  organizationIdParam: string,
  permissionKey: string,
  options: RoleGuardOptions = {}
) {
  return [
    requireAuth,
    assertStoreBelongsToOrganization(
      storeIdParam,
      organizationIdParam,
      options
    ),
    requireStorePermission(storeIdParam, permissionKey, options),
  ];
}
