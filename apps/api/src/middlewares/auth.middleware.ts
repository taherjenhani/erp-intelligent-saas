import type { PlatformRole, Role } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { writeAuditLog } from "../lib/audit";
import { AuthError } from "../lib/errors";
import { prisma } from "../lib/prisma";

export type AuthContext = {
  userId: string;
  email: string;
  role: Role;
  platformRole: PlatformRole;
  sessionId: string;
  storeIds: string[];
  storeRoles: Record<string, Role>;
  organizationIds: string[];
  organizationRoles: Record<string, Role>;
};

export async function requireAuth(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  try {
    const payload = await request.jwtVerify<{
      sub: string;
      sessionId: string;
    }>();

    const session = await prisma.session.findUnique({
      where: { id: payload.sessionId },
      include: {
        user: {
          include: {
            storeAccesses: {
              select: {
                storeId: true,
                role: true,
              },
            },
            memberships: {
              select: {
                organizationId: true,
                role: true,
              },
            },
          },
        },
      },
    });

    if (!session) {
      throw new AuthError(
        "AUTH_SESSION_NOT_FOUND",
        "Session not found"
      );
    }

    if (session.status !== "ACTIVE") {
      throw new AuthError("AUTH_SESSION_REVOKED", "Session revoked");
    }

    if (session.expiresAt <= new Date()) {
      throw new AuthError("AUTH_SESSION_EXPIRED", "Session expired");
    }

    if (session.userId !== payload.sub) {
      throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
    }

    if (!session.user.isActive) {
      throw new AuthError(
        "AUTH_ACCOUNT_DISABLED",
        "Account is disabled",
        403
      );
    }

    request.auth = {
      userId: session.user.id,
      email: session.user.email,
      role: session.user.role,
      platformRole: session.user.platformRole,
      sessionId: session.id,
      storeIds: session.user.storeAccesses.map(
        (access) => access.storeId
      ),
      storeRoles: Object.fromEntries(
        session.user.storeAccesses.map((access) => [
          access.storeId,
          access.role,
        ])
      ),
      organizationIds: session.user.memberships.map(
        (membership) => membership.organizationId
      ),
      organizationRoles: Object.fromEntries(
        session.user.memberships.map((membership) => [
          membership.organizationId,
          membership.role,
        ])
      ),
    };
  } catch (error) {
    await writeAuditLog({
      action: "ACCESS_DENIED",
      ipAddress: request.ip,
      userAgent: request.headers["user-agent"],
      metadata: {
        path: request.url,
      },
    });

    if (error instanceof AuthError) {
      throw error;
    }

    throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
  }
}
