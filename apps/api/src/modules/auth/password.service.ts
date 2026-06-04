import {
  buildPasswordResetMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import { hashPassword, verifyPassword } from "../../utils/hash";
import { writeAuthAudit } from "./auth-audit.service";
import { consumeAuthToken, createAuthToken } from "./auth-token.service";
import type {
  ChangePasswordInput,
  RequestPasswordResetInput,
  ResetPasswordInput,
} from "./auth.schema";
import type { AuthContextInput } from "./auth.types";

export async function requestPasswordReset(
  data: RequestPasswordResetInput,
  context: AuthContextInput = {}
) {
  const email = data.email.trim().toLowerCase();
  const user = await prisma.user.findUnique({
    where: {
      email,
    },
    select: {
      id: true,
      email: true,
      isActive: true,
    },
  });

  if (!user || !user.isActive) {
    return {
      resetToken: null,
    };
  }

  const { resetToken, passwordResetOutboxId } =
    await prisma.$transaction(async (tx) => {
      await tx.authToken.updateMany({
        where: {
          userId: user.id,
          purpose: "PASSWORD_RESET",
          usedAt: null,
        },
        data: {
          usedAt: new Date(),
        },
      });

      const token = await createAuthToken(
        user.id,
        "PASSWORD_RESET",
        tx
      );
      const queuedEmail = await enqueueEmail(
        tx,
        buildPasswordResetMessage(user.email, token)
      );

      return {
        resetToken: token,
        passwordResetOutboxId: queuedEmail.id,
      };
    });

  void processQueuedEmail(passwordResetOutboxId).catch((error) => {
    console.error("Inline email processing failed", error);
  });

  await writeAuthAudit(
    "PASSWORD_RESET_REQUESTED",
    context,
    user.id
  );

  return {
    resetToken,
  };
}

export async function resetPassword(
  data: ResetPasswordInput,
  context: AuthContextInput = {}
) {
  const password = await hashPassword(data.password);

  const authToken = await prisma.$transaction(async (tx) => {
    const consumedToken = await consumeAuthToken(
      data.token,
      "PASSWORD_RESET",
      "AUTH_INVALID_RESET_TOKEN",
      tx
    );

    await tx.user.update({
      where: {
        id: consumedToken.userId,
      },
      data: {
        password,
        sessions: {
          updateMany: {
            where: {
              status: "ACTIVE",
            },
            data: {
              status: "REVOKED",
            },
          },
        },
      },
    });

    await tx.refreshToken.updateMany({
      where: {
        session: {
          userId: consumedToken.userId,
        },
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    return consumedToken;
  });

  await writeAuthAudit(
    "PASSWORD_RESET_COMPLETED",
    context,
    authToken.userId
  );
}

export async function changePassword(
  userId: string,
  currentSessionId: string,
  data: ChangePasswordInput,
  context: AuthContextInput = {}
) {
  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      id: true,
      password: true,
    },
  });

  if (!user) {
    throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
  }

  const isPasswordValid = await verifyPassword(
    data.currentPassword,
    user.password
  );

  if (!isPasswordValid) {
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Current password is invalid"
    );
  }

  const password = await hashPassword(data.newPassword);

  await prisma.$transaction(async (tx) => {
    await tx.user.update({
      where: {
        id: user.id,
      },
      data: {
        password,
      },
    });

    await tx.session.updateMany({
      where: {
        userId: user.id,
        id: {
          not: currentSessionId,
        },
        status: "ACTIVE",
      },
      data: {
        status: "REVOKED",
      },
    });

    await tx.refreshToken.updateMany({
      where: {
        session: {
          userId: user.id,
          id: {
            not: currentSessionId,
          },
        },
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  });

  await writeAuthAudit("PASSWORD_CHANGED", context, user.id, {
    sessionId: currentSessionId,
  });
}
