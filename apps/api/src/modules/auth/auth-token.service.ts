import type { AuthTokenPurpose, Prisma } from "@prisma/client";

import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import {
  generateRandomToken,
  getTokenHashCandidates,
  hashToken,
} from "../../utils/token";

type PrismaClientLike = Prisma.TransactionClient | typeof prisma;

const AUTH_TOKEN_DURATION_MS = 30 * 60 * 1000;

export async function createAuthToken(
  userId: string,
  purpose: AuthTokenPurpose,
  client: PrismaClientLike = prisma
) {
  const token = generateRandomToken();

  await client.authToken.create({
    data: {
      tokenHash: await hashToken(token),
      purpose,
      userId,
      expiresAt: new Date(Date.now() + AUTH_TOKEN_DURATION_MS),
    },
  });

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
  const authToken = await client.authToken.findFirst({
    where: {
      tokenHash: {
        in: tokenHashes,
      },
      purpose,
      usedAt: null,
      expiresAt: {
        gt: now,
      },
    },
  });

  if (!authToken) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }

  const consumed = await client.authToken.updateMany({
    where: {
      id: authToken.id,
      usedAt: null,
      expiresAt: {
        gt: now,
      },
    },
    data: {
      usedAt: now,
    },
  });

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
  const authToken = await client.authToken.findFirst({
    where: {
      tokenHash: {
        in: tokenHashes,
      },
      purpose,
      usedAt: null,
      expiresAt: {
        gt: now,
      },
    },
  });

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
  const consumed = await client.authToken.updateMany({
    where: {
      id: authTokenId,
      usedAt: null,
      expiresAt: {
        gt: now,
      },
    },
    data: {
      usedAt: now,
    },
  });

  if (consumed.count !== 1) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }
}
