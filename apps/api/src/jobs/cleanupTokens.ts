import { prisma } from "../lib/prisma";

const REFRESH_TOKEN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

export async function cleanupExpiredTokens() {
  const now = new Date();
  const refreshCutoff = new Date(
    Date.now() - REFRESH_TOKEN_RETENTION_MS
  );

  const [authTokens, refreshTokens] = await prisma.$transaction([
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
  ]);

  return {
    authTokens: authTokens.count,
    refreshTokens: refreshTokens.count,
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
