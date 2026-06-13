import assert from "node:assert/strict";
import test from "node:test";
import "../test/setup-env";
import type { Role } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { PermissionError } from "../lib/errors";
import type { AuthContext } from "./auth.middleware";
import {
  requireOrganizationPermission,
  requireOrganizationRole,
  requireStoreInOrganization,
  requireStorePermission,
  type RoleAccess,
  type RoleGuardOptions,
} from "./role.middleware";

const reply = {} as FastifyReply;

const baseAuth: AuthContext = {
  userId: "user-1",
  email: "user@example.com",
  role: "EMPLOYEE",
  platformRole: "USER",
  sessionId: "session-1",
  storeIds: ["store-1"],
  storeRoles: {
    "store-1": "MANAGER",
  },
  organizationIds: ["org-1"],
  organizationRoles: {
    "org-1": "ADMIN",
  },
};

function request(
  auth: AuthContext | undefined,
  params: Record<string, string>
) {
  return {
    auth,
    params,
    ip: "127.0.0.1",
    headers: {
      "user-agent": "role-middleware-test",
    },
    url: "/test",
    correlationId: "test-correlation",
  } as unknown as FastifyRequest;
}

function access(overrides: Partial<RoleAccess> = {}): RoleAccess {
  return {
    roleHasPermission: async (role: Role, permissionKey: string) =>
      role === "MANAGER" && permissionKey === "stores.write",
    activeOrganizationExists: async (organizationId: string) =>
      organizationId === "org-1",
    activeStoreExists: async (storeId: string) => storeId === "store-1",
    storeBelongsToOrganization: async (
      storeId: string,
      organizationId: string
    ) => storeId === "store-1" && organizationId === "org-1",
    ...overrides,
  };
}

function deniedAuditCapture() {
  let metadata: unknown;
  const writeDeniedAudit: RoleGuardOptions["writeDeniedAudit"] = async (
    input
  ) => {
    metadata = input.metadata;
  };

  return {
    options: {
      writeDeniedAudit,
    },
    metadata: () => metadata as Record<string, unknown> | undefined,
  };
}

test("requireStorePermission allows scoped store permission", async () => {
  const guard = requireStorePermission("storeId", "stores.write", {
    access: access(),
  });

  await guard(request(baseAuth, { storeId: "store-1" }), reply);
});

test("requireStorePermission denies missing store permission with audit metadata", async () => {
  const audit = deniedAuditCapture();
  const guard = requireStorePermission("storeId", "stores.delete", {
    access: access(),
    ...audit.options,
  });

  await assert.rejects(
    () => guard(request(baseAuth, { storeId: "store-1" }), reply),
    PermissionError
  );
  assert.equal(audit.metadata()?.reason, "store_permission_missing");
  assert.equal(audit.metadata()?.storeId, "store-1");
});

test("requireStoreInOrganization denies cross-organization store access", async () => {
  const audit = deniedAuditCapture();
  const guard = requireStoreInOrganization("storeId", "organizationId", {
    access: access(),
    ...audit.options,
  });

  await assert.rejects(
    () =>
      guard(
        request(baseAuth, {
          storeId: "store-1",
          organizationId: "org-2",
        }),
        reply
      ),
    PermissionError
  );
  assert.equal(audit.metadata()?.reason, "store_not_in_organization");
});

test("requireOrganizationRole allows tenant admin role", async () => {
  const guard = requireOrganizationRole("organizationId", ["ADMIN"], {
    access: access(),
  });

  await guard(request(baseAuth, { organizationId: "org-1" }), reply);
});

test("requireOrganizationPermission checks tenant role permissions", async () => {
  const guard = requireOrganizationPermission(
    "organizationId",
    "users.write",
    {
      access: access({
        roleHasPermission: async (role, permissionKey) =>
          role === "ADMIN" && permissionKey === "users.write",
      }),
    }
  );

  await guard(request(baseAuth, { organizationId: "org-1" }), reply);
});
