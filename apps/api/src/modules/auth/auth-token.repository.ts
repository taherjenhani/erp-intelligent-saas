import type { AuthTokenPurpose, Prisma } from "@prisma/client";

import { prisma } from "../../lib/prisma";

export type PrismaClientLike = Prisma.TransactionClient | typeof prisma;

export function createAuthTokenRecord(
  input: {
    tokenHash: string;
    purpose: AuthTokenPurpose;
    userId: string;
    expiresAt: Date;
  },
  client: PrismaClientLike = prisma
) {
  return client.authToken.create({
    data: input,
  });
}

export function findUsableAuthTokenByHashes(
  input: {
    tokenHashes: string[];
    purpose: AuthTokenPurpose;
    now: Date;
  },
  client: PrismaClientLike = prisma
) {
  return client.authToken.findFirst({
    where: {
      tokenHash: {
        in: input.tokenHashes,
      },
      purpose: input.purpose,
      usedAt: null,
      expiresAt: {
        gt: input.now,
      },
    },
  });
}

export function markAuthTokenRecordUsed(
  input: {
    authTokenId: string;
    now: Date;
  },
  client: PrismaClientLike = prisma
) {
  return client.authToken.updateMany({
    where: {
      id: input.authTokenId,
      usedAt: null,
      expiresAt: {
        gt: input.now,
      },
    },
    data: {
      usedAt: input.now,
    },
  });
}
