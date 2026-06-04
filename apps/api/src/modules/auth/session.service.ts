import { Prisma } from "@prisma/client";

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
  if (
    session.userAgent &&
    context.userAgent &&
    session.userAgent !== context.userAgent
  ) {
    return false;
  }

  if (
    session.ipAddress &&
    context.ipAddress &&
    session.ipAddress !== context.ipAddress
  ) {
    return false;
  }

  return true;
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
    isWithinRefreshReuseGrace(token.rotatedAt) &&
    isSameRefreshContext(token.session, context) &&
    token.expiresAt > now &&
    token.session.expiresAt > now &&
    token.session.status === "ACTIVE" &&
    token.session.user.isActive
  );
}

async function createGraceRefreshResult(
  token: RefreshTokenWithSession,
  context: AuthContextInput
) {
  const concurrentRefreshToken = await createRefreshTokenRecord(
    token.familyId
  );
  const session = await prisma.$transaction(async (tx) => {
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
    await writeAuthAudit("LOGIN_FAILED", context, null, {
      email: normalizedEmail,
    });
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Invalid email or password"
    );
  }

  if (!user.isActive) {
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
    await writeAuthAudit("LOGIN_FAILED", context, user.id, {
      reason: "invalid_password",
    });
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Invalid email or password"
    );
  }

  if (!user.emailVerifiedAt) {
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
