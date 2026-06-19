import type { AuthTokenPurpose } from "@prisma/client";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import {
  generateRandomToken,
  getTokenHashCandidates,
  hashToken,
} from "../../utils/token";
import {
  createAuthTokenRecord,
  findUsableAuthTokenByHashes,
  markAuthTokenRecordUsed,
  type PrismaClientLike,
} from "./auth-token.repository";

export function authTokenTtlMs(purpose: AuthTokenPurpose) {
  switch (purpose) {
    case "EMAIL_VERIFICATION":
      return env.EMAIL_VERIFICATION_TOKEN_TTL_MS;
    case "PASSWORD_RESET":
      return env.PASSWORD_RESET_TOKEN_TTL_MS;
  }
}

export async function createAuthToken(
  userId: string,
  purpose: AuthTokenPurpose,
  client: PrismaClientLike = prisma
) {
  const token = generateRandomToken();
  const expiresAt = new Date(Date.now() + authTokenTtlMs(purpose));

  await createAuthTokenRecord(
    {
      tokenHash: await hashToken(token),
      purpose,
      userId,
      expiresAt,
    },
    client
  );

  return token;
}

export async function consumeAuthToken(
  token: string,
  purpose: AuthTokenPurpose,
  errorCode:
    | "AUTH_INVALID_RESET_TOKEN"
    | "AUTH_INVALID_VERIFICATION_TOKEN",
  client: PrismaClientLike = prisma
) {
  const now = new Date();
  const tokenHashes = await getTokenHashCandidates(token);
  const authToken = await findUsableAuthTokenByHashes(
    {
      tokenHashes,
      purpose,
      now,
    },
    client
  );

  if (!authToken) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }

  const consumed = await markAuthTokenRecordUsed(
    {
      authTokenId: authToken.id,
      now,
    },
    client
  );

  if (consumed.count !== 1) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }

  return authToken;
}

export async function findValidAuthToken(
  token: string,
  purpose: AuthTokenPurpose,
  errorCode:
    | "AUTH_INVALID_RESET_TOKEN"
    | "AUTH_INVALID_VERIFICATION_TOKEN",
  client: PrismaClientLike = prisma
) {
  const now = new Date();
  const tokenHashes = await getTokenHashCandidates(token);
  const authToken = await findUsableAuthTokenByHashes(
    {
      tokenHashes,
      purpose,
      now,
    },
    client
  );

  if (!authToken) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }

  return authToken;
}

export async function markAuthTokenUsed(
  authTokenId: string,
  errorCode:
    | "AUTH_INVALID_RESET_TOKEN"
    | "AUTH_INVALID_VERIFICATION_TOKEN",
  client: PrismaClientLike = prisma
) {
  const now = new Date();
  const consumed = await markAuthTokenRecordUsed(
    {
      authTokenId,
      now,
    },
    client
  );

  if (consumed.count !== 1) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }
}
