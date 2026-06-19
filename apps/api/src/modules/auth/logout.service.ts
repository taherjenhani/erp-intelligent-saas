import { prisma } from "../../lib/prisma";
import { getTokenHashCandidates } from "../../utils/token";
import { writeAuthAudit } from "./auth-audit.service";
import {
  findLogoutRefreshTokenByHashes,
  revokeAllActiveUserSessionsAndTokens,
  revokeSessionByRefreshToken,
} from "./auth.repository";
import type { AuthContextInput } from "./auth.types";

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
