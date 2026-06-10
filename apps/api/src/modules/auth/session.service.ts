import { Prisma } from "@prisma/client";
import crypto from "crypto";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import { createRefreshTokenRecord } from "../../utils/authTokens";
import { verifyPassword } from "../../utils/hash";
import { getTokenHashCandidates } from "../../utils/token";
import { writeAuthAudit } from "./auth-audit.service";
import { toPublicUser } from "./auth.mapper";
import type { LoginInput } from "./auth.schema";
import type { AuthContextInput } from "./auth.types";

const refreshTokenSessionInclude = {
  session: {
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
  },
} satisfies Prisma.RefreshTokenInclude;

type RefreshTokenWithSession = Prisma.RefreshTokenGetPayload<{
  include: typeof refreshTokenSessionInclude;
}>;

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
      CASE WHEN ${identity.maxFailures} <= 1 THEN ${lockedUntil} ELSE NULL END,
      ${now},
      ${now}
    )
    ON CONFLICT ("identityType", "identityKey") DO UPDATE SET
      "failedCount" = CASE
        WHEN "LoginLock"."lastFailureAt" IS NULL
          OR "LoginLock"."lastFailureAt" < ${windowStart}
          OR (
            "LoginLock"."lockedUntil" IS NOT NULL
            AND "LoginLock"."lockedUntil" < ${now}
          )
        THEN 1
        ELSE "LoginLock"."failedCount" + 1
      END,
      "lockedUntil" = CASE
        WHEN (
          CASE
            WHEN "LoginLock"."lastFailureAt" IS NULL
              OR "LoginLock"."lastFailureAt" < ${windowStart}
              OR (
                "LoginLock"."lockedUntil" IS NOT NULL
                AND "LoginLock"."lockedUntil" < ${now}
              )
            THEN 1
            ELSE "LoginLock"."failedCount" + 1
          END
        ) >= ${identity.maxFailures}
        THEN ${lockedUntil}
        ELSE NULL
      END,
      "lastFailureAt" = ${now},
      "updatedAt" = ${now}
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

async function recordLoginAttempt(input: {
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

async function assertLoginNotLocked(
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

async function revokeTokenFamily(familyId: string, sessionId: string) {
  await prisma.$transaction([
    prisma.refreshToken.updateMany({
      where: {
        familyId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    }),
    prisma.session.update({
      where: {
        id: sessionId,
      },
      data: {
        status: "REVOKED",
      },
    }),
  ]);
}

function isSameRefreshContext(
  session: {
    userAgent: string | null;
    ipAddress: string | null;
  },
  context: AuthContextInput
) {
  if (session.userAgent && session.userAgent !== context.userAgent) {
    return false;
  }

  if (session.ipAddress && session.ipAddress !== context.ipAddress) {
    return false;
  }

  return true;
}

function refreshContextHash(context: AuthContextInput) {
  return crypto
    .createHash("sha256")
    .update(context.userAgent ?? "")
    .update("\0")
    .update(context.ipAddress ?? "")
    .digest("hex");
}

function isWithinRefreshReuseGrace(rotatedAt: Date | null) {
  if (!rotatedAt) {
    return false;
  }

  return (
    Date.now() - rotatedAt.getTime() <=
    env.REFRESH_TOKEN_REUSE_GRACE_MS
  );
}

function canUseRefreshReuseGrace(
  token: RefreshTokenWithSession,
  context: AuthContextInput,
  now: Date
) {
  return (
    Boolean(token.replacedByTokenId) &&
    !token.graceConsumedAt &&
    isWithinRefreshReuseGrace(token.rotatedAt) &&
    isSameRefreshContext(token.session, context) &&
    token.expiresAt > now &&
    token.session.expiresAt > now &&
    token.session.status === "ACTIVE" &&
    token.session.user.isActive
  );
}

function canIgnoreSameContextRefreshReplay(
  token: RefreshTokenWithSession,
  context: AuthContextInput,
  now: Date
) {
  return (
    Boolean(token.replacedByTokenId) &&
    Boolean(token.graceConsumedAt) &&
    isWithinRefreshReuseGrace(token.rotatedAt) &&
    isSameRefreshContext(token.session, context) &&
    token.expiresAt > now &&
    token.session.expiresAt > now &&
    token.session.status === "ACTIVE" &&
    token.session.user.isActive
  );
}

async function throwIfSameContextRefreshReplay(
  tokenId: string,
  context: AuthContextInput,
  now: Date
) {
  const token = await prisma.refreshToken.findUnique({
    where: {
      id: tokenId,
    },
    include: refreshTokenSessionInclude,
  });

  if (!token || !canIgnoreSameContextRefreshReplay(token, context, now)) {
    return;
  }

  await writeAuthAudit(
    "REFRESH_TOKEN",
    context,
    token.session.userId,
    {
      sessionId: token.sessionId,
      sameContextReplaySuppressed: true,
    }
  );

  throw new AuthError(
    "AUTH_REFRESH_ALREADY_ROTATED",
    "Refresh token was already rotated",
    409
  );
}

async function createGraceRefreshResult(
  token: RefreshTokenWithSession,
  context: AuthContextInput
) {
  const now = new Date();
  const concurrentRefreshToken = await createRefreshTokenRecord(
    token.familyId
  );
  const session = await prisma.$transaction(async (tx) => {
    const consumedGrace = await tx.refreshToken.updateMany({
      where: {
        id: token.id,
        graceConsumedAt: null,
      },
      data: {
        graceConsumedAt: now,
      },
    });

    if (consumedGrace.count !== 1) {
      return null;
    }

    await tx.refreshToken.create({
      data: {
        ...concurrentRefreshToken.record,
        sessionId: token.sessionId,
      },
    });

    return tx.session.update({
      where: {
        id: token.sessionId,
      },
      data: {
        expiresAt: concurrentRefreshToken.record.expiresAt,
      },
    });
  });

  if (!session) {
    await throwIfSameContextRefreshReplay(token.id, context, now);
    await revokeTokenFamily(token.familyId, token.sessionId);
    await writeAuthAudit(
      "TOKEN_REUSE_DETECTED",
      context,
      token.session.userId,
      {
        sessionId: token.sessionId,
        reason: "refresh_grace_already_consumed",
      }
    );
    throw new AuthError(
      "AUTH_REFRESH_TOKEN_REUSED",
      "Refresh token reuse detected"
    );
  }

  await writeAuthAudit(
    "REFRESH_TOKEN",
    context,
    token.session.userId,
    {
      sessionId: token.sessionId,
      concurrentReuseGrace: true,
    }
  );

  return {
    refreshToken: concurrentRefreshToken.refreshToken,
    session,
    user: toPublicUser(token.session.user),
  };
}

async function tryCreateGraceRefreshResult(
  tokenId: string,
  context: AuthContextInput,
  now: Date
) {
  const rotatedToken = await prisma.refreshToken.findUnique({
    where: {
      id: tokenId,
    },
    include: refreshTokenSessionInclude,
  });

  if (
    !rotatedToken ||
    !rotatedToken.revokedAt ||
    !canUseRefreshReuseGrace(rotatedToken, context, now)
  ) {
    return null;
  }

  return createGraceRefreshResult(rotatedToken, context);
}

export async function loginUser(
  data: LoginInput,
  context: AuthContextInput = {}
) {
  const normalizedEmail = data.email.trim().toLowerCase();

  await assertLoginNotLocked(normalizedEmail, context);

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    include: {
      storeAccesses: {
        select: { storeId: true, role: true },
      },
      memberships: {
        select: { organizationId: true, role: true },
      },
    },
  });

  if (!user) {
    await recordLoginAttempt({
      email: normalizedEmail,
      context,
      success: false,
      reason: "user_not_found",
    });
    await writeAuthAudit("LOGIN_FAILED", context, null, {
      email: normalizedEmail,
    });
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Invalid email or password"
    );
  }

  if (!user.isActive) {
    await recordLoginAttempt({
      email: normalizedEmail,
      context,
      success: false,
      reason: "account_disabled",
      userId: user.id,
    });
    await writeAuthAudit("LOGIN_FAILED", context, user.id, {
      reason: "account_disabled",
    });
    throw new AuthError(
      "AUTH_ACCOUNT_DISABLED",
      "Account is disabled",
      403
    );
  }

  const isPasswordValid = await verifyPassword(
    data.password,
    user.password
  );

  if (!isPasswordValid) {
    await recordLoginAttempt({
      email: normalizedEmail,
      context,
      success: false,
      reason: "invalid_password",
      userId: user.id,
    });
    await writeAuthAudit("LOGIN_FAILED", context, user.id, {
      reason: "invalid_password",
    });
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Invalid email or password"
    );
  }

  if (!user.emailVerifiedAt) {
    await recordLoginAttempt({
      email: normalizedEmail,
      context,
      success: false,
      reason: "email_not_verified",
      userId: user.id,
    });
    await writeAuthAudit("LOGIN_FAILED", context, user.id, {
      reason: "email_not_verified",
    });
    throw new AuthError(
      "AUTH_EMAIL_NOT_VERIFIED",
      "Email address is not verified",
      403
    );
  }

  const refreshToken = await createRefreshTokenRecord();
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      userAgent: context.userAgent,
      ipAddress: context.ipAddress,
      expiresAt: refreshToken.record.expiresAt,
      refreshTokens: {
        create: refreshToken.record,
      },
    },
  });

  await writeAuthAudit("LOGIN_SUCCESS", context, user.id);
  await recordLoginAttempt({
    email: normalizedEmail,
    context,
    success: true,
    userId: user.id,
  });

  return {
    refreshToken: refreshToken.refreshToken,
    session,
    user: toPublicUser(user),
  };
}

export async function refreshSession(
  refreshToken: string,
  context: AuthContextInput = {}
) {
  const refreshTokenHashes = await getTokenHashCandidates(refreshToken);
  const matchedToken = await prisma.refreshToken.findFirst({
    where: {
      tokenHash: {
        in: refreshTokenHashes,
      },
    },
    include: refreshTokenSessionInclude,
  });

  if (!matchedToken) {
    throw new AuthError(
      "AUTH_INVALID_REFRESH_TOKEN",
      "Invalid refresh token"
    );
  }

  const now = new Date();

  if (matchedToken.revokedAt) {
    if (canUseRefreshReuseGrace(matchedToken, context, now)) {
      return createGraceRefreshResult(matchedToken, context);
    }

    await throwIfSameContextRefreshReplay(
      matchedToken.id,
      context,
      now
    );

    await revokeTokenFamily(
      matchedToken.familyId,
      matchedToken.sessionId
    );
    await writeAuthAudit(
      "TOKEN_REUSE_DETECTED",
      context,
      matchedToken.session.userId,
      { sessionId: matchedToken.sessionId }
    );
    throw new AuthError(
      "AUTH_REFRESH_TOKEN_REUSED",
      "Refresh token reuse detected"
    );
  }

  if (
    matchedToken.expiresAt <= now ||
    matchedToken.session.expiresAt <= now
  ) {
    await revokeTokenFamily(
      matchedToken.familyId,
      matchedToken.sessionId
    );
    throw new AuthError("AUTH_SESSION_EXPIRED", "Session expired");
  }

  if (matchedToken.session.status !== "ACTIVE") {
    throw new AuthError("AUTH_SESSION_REVOKED", "Session revoked");
  }

  if (!matchedToken.session.user.isActive) {
    throw new AuthError(
      "AUTH_ACCOUNT_DISABLED",
      "Account is disabled",
      403
    );
  }

  const newRefreshToken = await createRefreshTokenRecord(
    matchedToken.familyId
  );

  const session = await prisma.$transaction(async (tx) => {
    const updatedToken = await tx.refreshToken.updateMany({
      where: {
        id: matchedToken.id,
        revokedAt: null,
      },
      data: {
        revokedAt: now,
        rotatedAt: now,
      },
    });

    if (updatedToken.count !== 1) {
      return null;
    }

    const createdRefreshToken = await tx.refreshToken.create({
      data: {
        ...newRefreshToken.record,
        sessionId: matchedToken.sessionId,
      },
      select: {
        id: true,
      },
    });

    await tx.refreshToken.update({
      where: {
        id: matchedToken.id,
      },
      data: {
        replacedByTokenId: createdRefreshToken.id,
      },
    });

    await tx.refreshRotation.create({
      data: {
        previousRefreshTokenId: matchedToken.id,
        rotatedRefreshTokenId: createdRefreshToken.id,
        sessionId: matchedToken.sessionId,
        familyId: matchedToken.familyId,
        contextHash: refreshContextHash(context),
      },
    });

    return tx.session.update({
      where: {
        id: matchedToken.sessionId,
      },
      data: {
        expiresAt: newRefreshToken.record.expiresAt,
      },
    });
  });

  if (!session) {
    const graceRefresh = await tryCreateGraceRefreshResult(
      matchedToken.id,
      context,
      now
    );

    if (graceRefresh) {
      return graceRefresh;
    }

    await throwIfSameContextRefreshReplay(
      matchedToken.id,
      context,
      now
    );

    await revokeTokenFamily(
      matchedToken.familyId,
      matchedToken.sessionId
    );
    await writeAuthAudit(
      "TOKEN_REUSE_DETECTED",
      context,
      matchedToken.session.userId,
      { sessionId: matchedToken.sessionId }
    );
    throw new AuthError(
      "AUTH_REFRESH_TOKEN_REUSED",
      "Refresh token reuse detected"
    );
  }

  await writeAuthAudit(
    "REFRESH_TOKEN",
    context,
    matchedToken.session.userId
  );

  return {
    refreshToken: newRefreshToken.refreshToken,
    session,
    user: toPublicUser(matchedToken.session.user),
  };
}

export async function logoutUser(
  refreshToken: string,
  context: AuthContextInput = {}
) {
  const refreshTokenHashes = await getTokenHashCandidates(refreshToken);
  const matchedToken = await prisma.refreshToken.findFirst({
    where: {
      tokenHash: {
        in: refreshTokenHashes,
      },
    },
    include: {
      session: {
        select: {
          userId: true,
        },
      },
    },
  });

  if (!matchedToken) {
    return;
  }

  await prisma.$transaction([
    prisma.refreshToken.update({
      where: {
        id: matchedToken.id,
      },
      data: {
        revokedAt: new Date(),
      },
    }),
    prisma.session.update({
      where: {
        id: matchedToken.sessionId,
      },
      data: {
        status: "REVOKED",
      },
    }),
  ]);

  await writeAuthAudit(
    "LOGOUT",
    context,
    matchedToken.session.userId
  );
}

export async function logoutAllUserSessions(
  userId: string,
  context: AuthContextInput = {}
) {
  await prisma.$transaction([
    prisma.session.updateMany({
      where: {
        userId,
        status: "ACTIVE",
      },
      data: {
        status: "REVOKED",
      },
    }),
    prisma.refreshToken.updateMany({
      where: {
        session: {
          userId,
        },
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    }),
  ]);

  await writeAuthAudit("LOGOUT", context, userId, {
    allSessions: true,
  });
}
