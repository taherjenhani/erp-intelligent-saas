import {
  buildEmailVerificationMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { reportOperationalError } from "../../lib/operationalErrors";
import { prisma } from "../../lib/prisma";
import { writeAuthAudit } from "./auth-audit.service";
import { consumeAuthToken, createAuthToken } from "./auth-token.service";
import type {
  ResendEmailVerificationInput,
  VerifyEmailInput,
} from "./auth.schema";
import type { AuthContextInput } from "./auth.types";

export async function verifyEmail(
  data: VerifyEmailInput,
  context: AuthContextInput = {}
) {
  const authToken = await prisma.$transaction(async (tx) => {
    const consumedToken = await consumeAuthToken(
      data.token,
      "EMAIL_VERIFICATION",
      "AUTH_INVALID_VERIFICATION_TOKEN",
      tx
    );

    await tx.user.update({
      where: {
        id: consumedToken.userId,
      },
      data: {
        emailVerifiedAt: new Date(),
      },
    });

    return consumedToken;
  });

  await writeAuthAudit("EMAIL_VERIFIED", context, authToken.userId);
}

export async function resendEmailVerification(
  data: ResendEmailVerificationInput,
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
      emailVerifiedAt: true,
    },
  });

  if (!user || !user.isActive || user.emailVerifiedAt) {
    return {
      emailVerificationToken: null,
    };
  }

  const { emailVerificationToken, emailVerificationOutboxId } =
    await prisma.$transaction(async (tx) => {
      const now = new Date();

      await tx.authToken.updateMany({
        where: {
          userId: user.id,
          purpose: "EMAIL_VERIFICATION",
          usedAt: null,
        },
        data: {
          usedAt: now,
        },
      });

      const token = await createAuthToken(
        user.id,
        "EMAIL_VERIFICATION",
        tx
      );
      const queuedEmail = await enqueueEmail(
        tx,
        buildEmailVerificationMessage(user.email, token)
      );

      return {
        emailVerificationToken: token,
        emailVerificationOutboxId: queuedEmail.id,
      };
    });

  void processQueuedEmail(emailVerificationOutboxId).catch((error) => {
    reportOperationalError("inline_email_processing_failed", error, {
      outboxId: emailVerificationOutboxId,
      userId: user.id,
      purpose: "email_verification_resend",
    });
  });

  await writeAuthAudit(
    "EMAIL_VERIFICATION_REQUESTED",
    context,
    user.id
  );

  return {
    emailVerificationToken,
  };
}
