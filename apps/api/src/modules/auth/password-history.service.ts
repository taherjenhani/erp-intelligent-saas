import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import { verifyPassword } from "../../utils/hash";
import type { PrismaClientLike } from "./auth.repository";

export async function assertPasswordNotRecentlyUsed(
  userId: string,
  password: string,
  currentPasswordHash?: string | null,
  client: PrismaClientLike = prisma
) {
  if (env.PASSWORD_HISTORY_LIMIT === 0) {
    return;
  }

  const recent = await client.passwordHistory.findMany({
    where: {
      userId,
    },
    orderBy: {
      createdAt: "desc",
    },
    take: env.PASSWORD_HISTORY_LIMIT,
    select: {
      passwordHash: true,
    },
  });
  const hashes = [
    ...(currentPasswordHash ? [currentPasswordHash] : []),
    ...recent.map((entry) => entry.passwordHash),
  ];

  for (const hash of [...new Set(hashes)]) {
    if (await verifyPassword(password, hash)) {
      throw new AuthError(
        "AUTH_PASSWORD_REUSED",
        "Password was used recently",
        400
      );
    }
  }
}

export async function rememberPassword(
  userId: string,
  passwordHash: string,
  client: PrismaClientLike = prisma
) {
  if (env.PASSWORD_HISTORY_LIMIT === 0) {
    return;
  }

  await client.passwordHistory.create({
    data: {
      userId,
      passwordHash,
    },
  });

  const staleEntries = await client.passwordHistory.findMany({
    where: {
      userId,
    },
    orderBy: {
      createdAt: "desc",
    },
    skip: env.PASSWORD_HISTORY_LIMIT,
    select: {
      id: true,
    },
  });

  if (staleEntries.length === 0) {
    return;
  }

  await client.passwordHistory.deleteMany({
    where: {
      id: {
        in: staleEntries.map((entry) => entry.id),
      },
    },
  });
}
