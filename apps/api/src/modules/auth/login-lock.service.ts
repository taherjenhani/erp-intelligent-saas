import { Prisma } from "@prisma/client";
import crypto from "crypto";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import type { AuthContextInput } from "./auth.types";

const LOCKOUT_REASONS = ["user_not_found", "invalid_password"];

type LoginLockIdentity = {
  identityType: "EMAIL" | "IP";
  identityKey: string;
  maxFailures: number;
};

function loginLockIdentities(
  email: string,
  context: AuthContextInput
): LoginLockIdentity[] {
  return [
    {
      identityType: "EMAIL",
      identityKey: email,
      maxFailures: env.LOGIN_ATTEMPT_EMAIL_MAX,
    },
    ...(context.ipAddress
      ? [
          {
            identityType: "IP" as const,
            identityKey: context.ipAddress,
            maxFailures: env.LOGIN_ATTEMPT_IP_MAX,
          },
        ]
      : []),
  ];
}

async function recordLoginFailureLock(
  client: Prisma.TransactionClient,
  identity: LoginLockIdentity,
  now: Date
) {
  const windowStart = new Date(
    now.getTime() - env.LOGIN_ATTEMPT_WINDOW_MS
  );
  const lockedUntil = new Date(
    now.getTime() + env.LOGIN_ATTEMPT_WINDOW_MS
  );

  await client.$executeRaw`
    INSERT INTO "LoginLock" (
      "id",
      "identityType",
      "identityKey",
      "failedCount",
      "lockedUntil",
      "lastFailureAt",
      "updatedAt"
    )
    VALUES (
      ${crypto.randomUUID()},
      ${identity.identityType}::"LoginLockIdentityType",
      ${identity.identityKey},
      1,
      CASE WHEN ${identity.maxFailures} <= 1 THEN ${lockedUntil}::timestamp ELSE NULL::timestamp END,
      ${now}::timestamp,
      ${now}::timestamp
    )
    ON CONFLICT ("identityType", "identityKey") DO UPDATE SET
      "failedCount" = CASE
        WHEN "LoginLock"."lastFailureAt" IS NULL
          OR "LoginLock"."lastFailureAt" < ${windowStart}::timestamp
          OR (
            "LoginLock"."lockedUntil" IS NOT NULL
            AND "LoginLock"."lockedUntil" < ${now}::timestamp
          )
        THEN 1
        ELSE "LoginLock"."failedCount" + 1
      END,
      "lockedUntil" = CASE
        WHEN (
          CASE
            WHEN "LoginLock"."lastFailureAt" IS NULL
              OR "LoginLock"."lastFailureAt" < ${windowStart}::timestamp
              OR (
                "LoginLock"."lockedUntil" IS NOT NULL
                AND "LoginLock"."lockedUntil" < ${now}::timestamp
              )
            THEN 1
            ELSE "LoginLock"."failedCount" + 1
          END
        ) >= ${identity.maxFailures}
        THEN ${lockedUntil}::timestamp
        ELSE NULL::timestamp
      END,
      "lastFailureAt" = ${now}::timestamp,
      "updatedAt" = ${now}::timestamp
  `;
}

async function resetLoginLocks(
  client: Prisma.TransactionClient,
  email: string,
  context: AuthContextInput
) {
  const identities = loginLockIdentities(email, context);

  if (identities.length === 0) {
    return;
  }

  await client.loginLock.updateMany({
    where: {
      OR: identities.map((identity) => ({
        identityType: identity.identityType,
        identityKey: identity.identityKey,
      })),
    },
    data: {
      failedCount: 0,
      lockedUntil: null,
      lastSuccessAt: new Date(),
    },
  });
}

export async function recordLoginAttempt(input: {
  email: string;
  context: AuthContextInput;
  success: boolean;
  reason?: string;
  userId?: string | null;
}) {
  await prisma.$transaction(async (tx) => {
    await tx.loginAttempt.create({
      data: {
        email: input.email,
        userId: input.userId ?? null,
        ipAddress: input.context.ipAddress,
        userAgent: input.context.userAgent,
        success: input.success,
        reason: input.reason,
      },
    });

    if (input.success) {
      await resetLoginLocks(tx, input.email, input.context);
      return;
    }

    if (!input.reason || !LOCKOUT_REASONS.includes(input.reason)) {
      return;
    }

    const now = new Date();

    for (const identity of loginLockIdentities(
      input.email,
      input.context
    )) {
      await recordLoginFailureLock(tx, identity, now);
    }
  });
}

export async function assertLoginNotLocked(
  email: string,
  context: AuthContextInput
) {
  const identities = loginLockIdentities(email, context);
  const now = new Date();
  const locks = await prisma.loginLock.findMany({
    where: {
      OR: identities.map((identity) => ({
        identityType: identity.identityType,
        identityKey: identity.identityKey,
        lockedUntil: {
          gt: now,
        },
      })),
    },
    select: {
      id: true,
    },
    take: 1,
  });

  if (locks.length > 0) {
    throw new AuthError(
      "AUTH_TOO_MANY_ATTEMPTS",
      "Too many login attempts, please try again later",
      429
    );
  }
}
