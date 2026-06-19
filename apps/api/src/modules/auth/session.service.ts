import crypto from "crypto";
import type {
  SessionStatus,
  SessionTerminationReason,
} from "@prisma/client";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import { createRefreshTokenRecord } from "../../utils/authTokens";
import {
  activePasswordPepperKeyId,
  hashPassword,
  verifyPassword,
} from "../../utils/hash";
import { getTokenHashCandidates } from "../../utils/token";
import { writeAuthAudit } from "./auth-audit.service";
import { toPublicUser } from "./auth.mapper";
import {
  createSessionWithRefreshToken,
  findLoginUserByEmail,
  findLogoutRefreshTokenByHashes,
  findRefreshRotationReplay,
  findRefreshTokenByHashesWithSession,
  findRefreshTokenByIdWithSession,
  type RefreshTokenWithSession,
  revokeAllActiveUserSessionsAndTokens,
  revokeRefreshTokenFamilyAndSession,
  revokeSessionByRefreshToken,
  updateUserPasswordHashIfCurrent,
} from "./auth.repository";
import {
  assertLoginNotLocked,
  recordLoginAttempt,
} from "./login-lock.service";
import type { LoginInput } from "./auth.schema";
import type { AuthContextInput } from "./auth.types";

const REFRESH_IDEMPOTENCY_VALUE_PREFIX = "enc:v1:";

async function revokeTokenFamily(
  familyId: string,
  sessionId: string,
  terminatedReason: SessionTerminationReason,
  sessionStatus?: SessionStatus
) {
  await prisma.$transaction((tx) =>
    revokeRefreshTokenFamilyAndSession(
      {
        familyId,
        sessionId,
        terminatedBy: "system",
        terminatedReason,
        sessionStatus,
      },
      tx
    )
  );
}

async function rehashPasswordPepperIfNeeded(input: {
  userId: string;
  password: string;
  currentPasswordHash: string;
  passwordPepperKeyId?: string | null;
}) {
  const activeKeyId = activePasswordPepperKeyId();

  if (input.passwordPepperKeyId === activeKeyId) {
    return;
  }

  await updateUserPasswordHashIfCurrent({
    userId: input.userId,
    currentPasswordHash: input.currentPasswordHash,
    password: await hashPassword(input.password),
    passwordPepperKeyId: activeKeyId,
  });
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

function normalizeDeviceName(userAgent?: string | null) {
  const normalized = userAgent?.trim();

  if (!normalized) {
    return null;
  }

  return normalized.slice(0, 120);
}

function sessionDeviceFingerprintHash(context: AuthContextInput) {
  const userAgent = context.userAgent?.trim() ?? "";
  const ipAddress = context.ipAddress?.trim() ?? "";

  if (!userAgent && !ipAddress) {
    return null;
  }

  return crypto
    .createHash("sha256")
    .update("session-device-v1")
    .update("\0")
    .update(userAgent)
    .update("\0")
    .update(ipAddress)
    .digest("hex");
}

function refreshIdempotencyKeyHash(context: AuthContextInput) {
  if (!context.idempotencyKey) {
    return null;
  }

  return crypto
    .createHmac("sha256", env.REFRESH_IDEMPOTENCY_SECRET)
    .update(context.idempotencyKey)
    .digest("hex");
}

function refreshIdempotencyEncryptionKey() {
  return crypto
    .createHash("sha256")
    .update(env.REFRESH_IDEMPOTENCY_SECRET)
    .digest();
}

function encryptRefreshIdempotencyValue(value: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    refreshIdempotencyEncryptionKey(),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return `${REFRESH_IDEMPOTENCY_VALUE_PREFIX}${Buffer.concat([
    iv,
    tag,
    encrypted,
  ]).toString("base64url")}`;
}

function decryptRefreshIdempotencyValue(value: string) {
  if (!value.startsWith(REFRESH_IDEMPOTENCY_VALUE_PREFIX)) {
    throw new Error("Invalid refresh idempotency payload");
  }

  const payload = Buffer.from(
    value.slice(REFRESH_IDEMPOTENCY_VALUE_PREFIX.length),
    "base64url"
  );
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const encrypted = payload.subarray(28);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    refreshIdempotencyEncryptionKey(),
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]).toString("utf8");
}

async function tryReplayRefreshIdempotencyResult(
  token: RefreshTokenWithSession,
  context: AuthContextInput,
  now: Date
) {
  const idempotencyKeyHash = refreshIdempotencyKeyHash(context);

  if (!idempotencyKeyHash) {
    return null;
  }

  const rotation = await findRefreshRotationReplay({
    previousRefreshTokenId: token.id,
    idempotencyKeyHash,
    contextHash: refreshContextHash(context),
    now,
  });

  if (!rotation?.responseRefreshToken) {
    return null;
  }

  const activeRotatedToken = await findRefreshTokenByIdWithSession(
    rotation.rotatedRefreshTokenId
  );

  if (
    !activeRotatedToken ||
    activeRotatedToken.revokedAt ||
    activeRotatedToken.expiresAt <= now ||
    activeRotatedToken.sessionId !== token.sessionId ||
    activeRotatedToken.session.status !== "ACTIVE" ||
    activeRotatedToken.session.expiresAt <= now ||
    !activeRotatedToken.session.user.isActive
  ) {
    return null;
  }

  await prisma.session.updateMany({
    where: {
      id: activeRotatedToken.sessionId,
      status: "ACTIVE",
    },
    data: {
      lastUsedAt: now,
    },
  });

  await writeAuthAudit(
    "REFRESH_TOKEN",
    context,
    activeRotatedToken.session.userId,
    {
      sessionId: activeRotatedToken.sessionId,
      idempotencyReplay: true,
    }
  );

  return {
    refreshToken: decryptRefreshIdempotencyValue(
      rotation.responseRefreshToken
    ),
    session: activeRotatedToken.session,
    user: toPublicUser(activeRotatedToken.session.user),
  };
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
  const token = await findRefreshTokenByIdWithSession(tokenId);

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
        lastUsedAt: now,
      },
    });
  });

  if (!session) {
    await throwIfSameContextRefreshReplay(token.id, context, now);
    await revokeTokenFamily(
      token.familyId,
      token.sessionId,
      "REFRESH_TOKEN_REUSE"
    );
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
  const rotatedToken = await findRefreshTokenByIdWithSession(tokenId);

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

  const user = await findLoginUserByEmail(normalizedEmail);

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
    user.password,
    user.passwordPepperKeyId
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

  await rehashPasswordPepperIfNeeded({
    userId: user.id,
    password: data.password,
    currentPasswordHash: user.password,
    passwordPepperKeyId: user.passwordPepperKeyId,
  });

  const refreshToken = await createRefreshTokenRecord();
  const now = new Date();
  const session = await createSessionWithRefreshToken({
    userId: user.id,
    userAgent: context.userAgent,
    ipAddress: context.ipAddress,
    lastUsedAt: now,
    deviceName: normalizeDeviceName(context.userAgent),
    deviceFingerprintHash: sessionDeviceFingerprintHash(context),
    expiresAt: refreshToken.record.expiresAt,
    refreshTokenRecord: refreshToken.record,
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
  const matchedToken = await findRefreshTokenByHashesWithSession(
    refreshTokenHashes
  );

  if (!matchedToken) {
    throw new AuthError(
      "AUTH_INVALID_REFRESH_TOKEN",
      "Invalid refresh token"
    );
  }

  const now = new Date();

  if (matchedToken.revokedAt) {
    const idempotencyReplay =
      await tryReplayRefreshIdempotencyResult(
        matchedToken,
        context,
        now
      );

    if (idempotencyReplay) {
      return idempotencyReplay;
    }

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
      matchedToken.sessionId,
      "REFRESH_TOKEN_REUSE"
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
      matchedToken.sessionId,
      "SESSION_EXPIRED",
      "EXPIRED"
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
  const idempotencyKeyHash = refreshIdempotencyKeyHash(context);

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
        idempotencyKeyHash,
        responseRefreshToken: idempotencyKeyHash
          ? encryptRefreshIdempotencyValue(
              newRefreshToken.refreshToken
            )
          : undefined,
        idempotencyExpiresAt: idempotencyKeyHash
          ? new Date(
              now.getTime() + env.REFRESH_IDEMPOTENCY_TTL_MS
            )
          : undefined,
      },
    });

    return tx.session.update({
      where: {
        id: matchedToken.sessionId,
      },
      data: {
        expiresAt: newRefreshToken.record.expiresAt,
        lastUsedAt: now,
      },
    });
  });

  if (!session) {
    const idempotencyReplay =
      await tryReplayRefreshIdempotencyResult(
        matchedToken,
        context,
        new Date()
      );

    if (idempotencyReplay) {
      return idempotencyReplay;
    }

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
      matchedToken.sessionId,
      "REFRESH_TOKEN_REUSE"
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
  const matchedToken = await findLogoutRefreshTokenByHashes(
    refreshTokenHashes
  );

  if (!matchedToken) {
    return;
  }

  await prisma.$transaction((tx) =>
    revokeSessionByRefreshToken(
      {
        refreshTokenId: matchedToken.id,
        sessionId: matchedToken.sessionId,
        terminatedBy: matchedToken.session.userId,
        terminatedReason: "LOGOUT",
      },
      tx
    )
  );

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
  await prisma.$transaction((tx) =>
    revokeAllActiveUserSessionsAndTokens(userId, tx, {
      terminatedBy: userId,
      terminatedReason: "LOGOUT_ALL",
    })
  );

  await writeAuthAudit("LOGOUT", context, userId, {
    allSessions: true,
  });
}
