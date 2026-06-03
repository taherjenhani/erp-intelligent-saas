import type { Role, Session } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";

import { env } from "../config/env";
import {
  generateFamilyId,
  generateRandomToken,
  hashToken,
} from "./token";

export const REFRESH_TOKEN_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
export const REFRESH_TOKEN_MAX_AGE_MS =
  REFRESH_TOKEN_MAX_AGE_SECONDS * 1000;

export type AuthUserPayload = {
  id: string;
  email: string;
  role: Role;
  storeIds: string[];
};

export type RefreshTokenRecord = {
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
};

export async function createRefreshTokenRecord(
  familyId = generateFamilyId()
): Promise<{
  refreshToken: string;
  record: RefreshTokenRecord;
}> {
  const refreshToken = generateRandomToken();

  return {
    refreshToken,
    record: {
      tokenHash: await hashToken(refreshToken),
      familyId,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_MAX_AGE_MS),
    },
  };
}

export function signAccessToken(
  request: FastifyRequest,
  user: AuthUserPayload,
  sessionId: string
) {
  return request.server.jwt.sign(
    {
      email: user.email,
      role: user.role,
      sessionId,
      storeIds: user.storeIds,
    },
    {
      sub: user.id,
      expiresIn: "15m",
    }
  );
}

export function setRefreshCookie(
  reply: FastifyReply,
  refreshToken: string
) {
  reply.setCookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: "strict",
    domain: env.COOKIE_DOMAIN,
    path: "/api/auth",
    maxAge: REFRESH_TOKEN_MAX_AGE_SECONDS,
  });
}

export function clearRefreshCookie(reply: FastifyReply) {
  reply.clearCookie("refreshToken", {
    domain: env.COOKIE_DOMAIN,
    path: "/api/auth",
  });
}

export function toAuthResponse(
  request: FastifyRequest,
  user: AuthUserPayload,
  session: Pick<Session, "id">,
  refreshToken: string
) {
  return {
    accessToken: signAccessToken(request, user, session.id),
    refreshToken,
    user,
  };
}
