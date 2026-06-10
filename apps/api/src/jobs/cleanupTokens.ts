import { prisma } from "../lib/prisma";

const REFRESH_TOKEN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const LOGIN_ATTEMPT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
const LOGIN_LOCK_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

export async function cleanupExpiredTokens() {
  const now = new Date();
  const refreshCutoff = new Date(
    Date.now() - REFRESH_TOKEN_RETENTION_MS
  );
  const loginAttemptCutoff = new Date(
    Date.now() - LOGIN_ATTEMPT_RETENTION_MS
  );
  const loginLockCutoff = new Date(
    Date.now() - LOGIN_LOCK_RETENTION_MS
  );

  const [
    authTokens,
    refreshTokens,
    loginAttempts,
    loginLocks,
    refreshIdempotencyResponses,
  ] =
    await prisma.$transaction([
      prisma.authToken.deleteMany({
        where: {
          expiresAt: {
            lt: now,
          },
        },
      }),
      prisma.refreshToken.deleteMany({
        where: {
          expiresAt: {
            lt: refreshCutoff,
          },
        },
      }),
      prisma.loginAttempt.deleteMany({
        where: {
          createdAt: {
            lt: loginAttemptCutoff,
          },
        },
      }),
      prisma.loginLock.deleteMany({
        where: {
          updatedAt: {
            lt: loginLockCutoff,
          },
          OR: [
            { lockedUntil: null },
            {
              lockedUntil: {
                lt: now,
              },
            },
          ],
        },
      }),
      prisma.refreshRotation.updateMany({
        where: {
          idempotencyExpiresAt: {
            lt: now,
          },
          responseRefreshToken: {
            not: null,
          },
        },
        data: {
          responseRefreshToken: null,
        },
      }),
    ]);

  return {
    authTokens: authTokens.count,
    refreshTokens: refreshTokens.count,
    loginAttempts: loginAttempts.count,
    loginLocks: loginLocks.count,
    refreshIdempotencyResponses:
      refreshIdempotencyResponses.count,
  };
}

if (require.main === module) {
  cleanupExpiredTokens()
    .then((result) => {
      console.log("Expired tokens cleanup completed", result);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}
