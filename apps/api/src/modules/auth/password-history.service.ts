import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import {
  activePasswordPepperKeyId,
  verifyPassword,
} from "../../utils/hash";
import type { PrismaClientLike } from "./auth.repository";

type PasswordHashCandidate = {
  passwordHash: string;
  passwordPepperKeyId?: string | null;
};

export async function assertPasswordNotRecentlyUsed(
  userId: string,
  password: string,
  currentPasswordHash?: string | null,
  currentPasswordPepperKeyId?: string | null,
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
      passwordPepperKeyId: true,
    },
  });
  const candidates: PasswordHashCandidate[] = [
    ...(currentPasswordHash
      ? [
          {
            passwordHash: currentPasswordHash,
            passwordPepperKeyId: currentPasswordPepperKeyId,
          },
        ]
      : []),
    ...recent,
  ];
  const seen = new Set<string>();

  for (const candidate of candidates) {
    if (seen.has(candidate.passwordHash)) {
      continue;
    }

    seen.add(candidate.passwordHash);

    if (
      await verifyPassword(
        password,
        candidate.passwordHash,
        candidate.passwordPepperKeyId
      )
    ) {
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
      passwordPepperKeyId: activePasswordPepperKeyId(),
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
