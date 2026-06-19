import {
  buildPasswordResetMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { reportOperationalError } from "../../lib/operationalErrors";
import { prisma } from "../../lib/prisma";
import {
  activePasswordPepperKeyId,
  hashPassword,
  verifyPassword,
} from "../../utils/hash";
import { writeAuthAudit } from "./auth-audit.service";
import { assertForgotPasswordActionAllowed } from "./auth-action-rate-limit.service";
import {
  findPasswordResetUser,
  findUserPasswordById,
  updatePasswordAndRevokeOtherSessions,
} from "./auth.repository";
import {
  createAuthToken,
  findValidAuthToken,
  markAuthTokenUsed,
} from "./auth-token.service";
import type {
  ChangePasswordInput,
  RequestPasswordResetInput,
  ResetPasswordInput,
} from "./auth.schema";
import type { AuthContextInput } from "./auth.types";
import {
  assertPasswordNotRecentlyUsed,
  rememberPassword,
} from "./password-history.service";

export async function requestPasswordReset(
  data: RequestPasswordResetInput,
  context: AuthContextInput = {}
) {
  const email = data.email.trim().toLowerCase();

  await assertForgotPasswordActionAllowed(email);

  const user = await findPasswordResetUser(email);

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
    reportOperationalError("inline_email_processing_failed", error, {
      outboxId: passwordResetOutboxId,
      purpose: "password_reset",
    });
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
  const authToken = await prisma.$transaction(async (tx) => {
    const validToken = await findValidAuthToken(
      data.token,
      "PASSWORD_RESET",
      "AUTH_INVALID_RESET_TOKEN",
      tx
    );
    const user = await findUserPasswordById(
      validToken.userId,
      tx
    );

    if (!user) {
      throw new AuthError(
        "AUTH_INVALID_RESET_TOKEN",
        "Invalid or expired token"
      );
    }

    await assertPasswordNotRecentlyUsed(
      validToken.userId,
      data.password,
      user.password,
      user.passwordPepperKeyId,
      tx
    );

    const password = await hashPassword(data.password);

    await markAuthTokenUsed(
      validToken.id,
      "AUTH_INVALID_RESET_TOKEN",
      tx
    );

    await updatePasswordAndRevokeOtherSessions(
      {
        userId: validToken.userId,
        password,
        passwordPepperKeyId: activePasswordPepperKeyId(),
        terminatedBy: validToken.userId,
        terminatedReason: "PASSWORD_RESET",
      },
      tx
    );
    await rememberPassword(validToken.userId, password, tx);

    return validToken;
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
  const user = await findUserPasswordById(userId);

  if (!user) {
    throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
  }

  const isPasswordValid = await verifyPassword(
    data.currentPassword,
    user.password,
    user.passwordPepperKeyId
  );

  if (!isPasswordValid) {
    throw new AuthError(
      "AUTH_INVALID_CREDENTIALS",
      "Current password is invalid"
    );
  }

  await assertPasswordNotRecentlyUsed(
    user.id,
    data.newPassword,
    user.password,
    user.passwordPepperKeyId
  );

  const password = await hashPassword(data.newPassword);
  await prisma.$transaction(async (tx) => {
    await updatePasswordAndRevokeOtherSessions(
      {
        userId: user.id,
        password,
        passwordPepperKeyId: activePasswordPepperKeyId(),
        keepSessionId: currentSessionId,
        terminatedBy: user.id,
        terminatedReason: "PASSWORD_CHANGED",
      },
      tx
    );
    await rememberPassword(user.id, password, tx);
  });

  await writeAuthAudit("PASSWORD_CHANGED", context, user.id, {
    sessionId: currentSessionId,
  });
}
