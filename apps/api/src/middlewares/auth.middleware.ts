import type { Role } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { writeAuditLog } from "../lib/audit";
import { AuthError } from "../lib/errors";
import { prisma } from "../lib/prisma";

export type AuthContext = {
  userId: string;
  email: string;
  role: Role;
  sessionId: string;
  storeIds: string[];
};

export async function requireAuth(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  try {
    const payload = await request.jwtVerify<{
      sub: string;
      email: string;
      role: Role;
      sessionId: string;
      storeIds?: string[];
    }>();

    const session = await prisma.session.findUnique({
      where: { id: payload.sessionId },
      select: {
        status: true,
        expiresAt: true,
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

    request.auth = {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
      sessionId: payload.sessionId,
      storeIds: payload.storeIds ?? [],
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
