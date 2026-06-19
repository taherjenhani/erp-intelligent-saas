import {
  Prisma,
  type AuthActionRateLimitAction,
} from "@prisma/client";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";

const EMAIL_ACTION_WINDOW_MS = 60 * 60 * 1000;
const MAX_SERIALIZATION_RETRIES = 2;

function normalizeIdentityKey(identityKey: string | null | undefined) {
  const normalized = identityKey?.trim().toLowerCase();

  if (!normalized) {
    return "unknown";
  }

  return normalized.slice(0, 256);
}

async function runAuthActionLimitCheck(input: {
  action: AuthActionRateLimitAction;
  identityKey: string;
  maxAttempts: number;
  windowMs: number;
}) {
  const now = new Date();
  const cutoff = new Date(now.getTime() - input.windowMs);

  return prisma.$transaction(
    async (tx) => {
      const existing = await tx.authActionRateLimit.findUnique({
        where: {
          action_identityKey: {
            action: input.action,
            identityKey: input.identityKey,
          },
        },
      });

      if (existing?.lockedUntil && existing.lockedUntil > now) {
        return {
          allowed: false,
          lockedUntil: existing.lockedUntil,
        };
      }

      if (!existing || existing.windowStartedAt <= cutoff) {
        await tx.authActionRateLimit.upsert({
          where: {
            action_identityKey: {
              action: input.action,
              identityKey: input.identityKey,
            },
          },
          create: {
            action: input.action,
            identityKey: input.identityKey,
            attempts: 1,
            windowStartedAt: now,
            lockedUntil: null,
          },
          update: {
            attempts: 1,
            windowStartedAt: now,
            lockedUntil: null,
          },
        });

        return {
          allowed: true,
          lockedUntil: null,
        };
      }

      const attempts = existing.attempts + 1;
      const lockedUntil =
        attempts > input.maxAttempts
          ? new Date(existing.windowStartedAt.getTime() + input.windowMs)
          : null;

      await tx.authActionRateLimit.update({
        where: {
          action_identityKey: {
            action: input.action,
            identityKey: input.identityKey,
          },
        },
        data: {
          attempts,
          lockedUntil,
        },
      });

      return {
        allowed: attempts <= input.maxAttempts,
        lockedUntil,
      };
    },
    {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    }
  );
}

async function assertAuthActionAllowed(
  input: {
    action: AuthActionRateLimitAction;
    identityKey: string | null | undefined;
    maxAttempts: number;
    windowMs?: number;
  },
  retry = 0
) {
  try {
    const result = await runAuthActionLimitCheck({
      action: input.action,
      identityKey: normalizeIdentityKey(input.identityKey),
      maxAttempts: input.maxAttempts,
      windowMs: input.windowMs ?? EMAIL_ACTION_WINDOW_MS,
    });

    if (!result.allowed) {
      throw new AuthError(
        "RATE_LIMIT_EXCEEDED",
        "Too many requests. Please try again later.",
        429
      );
    }
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === "P2034" &&
      retry < MAX_SERIALIZATION_RETRIES
    ) {
      return assertAuthActionAllowed(input, retry + 1);
    }

    throw error;
  }
}

export function assertForgotPasswordActionAllowed(email: string) {
  return assertAuthActionAllowed({
    action: "FORGOT_PASSWORD",
    identityKey: email,
    maxAttempts: env.AUTH_FORGOT_PASSWORD_MAX_PER_HOUR,
  });
}

export function assertResendVerificationActionAllowed(email: string) {
  return assertAuthActionAllowed({
    action: "RESEND_VERIFICATION",
    identityKey: email,
    maxAttempts: env.AUTH_RESEND_VERIFICATION_MAX_PER_HOUR,
  });
}

export function assertRegisterActionAllowed(ipAddress?: string | null) {
  return assertAuthActionAllowed({
    action: "REGISTER_IP",
    identityKey: ipAddress,
    maxAttempts: env.AUTH_REGISTER_MAX_PER_HOUR_PER_IP,
  });
}
