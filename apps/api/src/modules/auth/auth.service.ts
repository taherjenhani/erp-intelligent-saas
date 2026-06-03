import type {
  AuditAction,
  AuthTokenPurpose,
  Prisma,
} from "@prisma/client";

import { writeAuditLog } from "../../lib/audit";
import {
  sendEmailVerification,
  sendPasswordReset,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import {
  createRefreshTokenRecord,
  REFRESH_TOKEN_MAX_AGE_MS,
} from "../../utils/authTokens";
import { hashPassword, verifyPassword } from "../../utils/hash";
import { generateRandomToken, hashToken } from "../../utils/token";
import type {
  ChangePasswordInput,
  LoginInput,
  RegisterInput,
  RequestPasswordResetInput,
  ResetPasswordInput,
  VerifyEmailInput,
} from "./auth.schema";

type AuthContextInput = {
  ipAddress?: string | null;
  userAgent?: string | null;
};

const AUTH_TOKEN_DURATION_MS = 30 * 60 * 1000;

function getSessionExpiry() {
  return new Date(Date.now() + REFRESH_TOKEN_MAX_AGE_MS);
}

function toPublicUser(user: {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: "SUPER_ADMIN" | "ADMIN" | "MANAGER" | "EMPLOYEE";
  emailVerifiedAt?: Date | null;
  storeAccesses: { storeId: string }[];
}) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
    emailVerified: Boolean(user.emailVerifiedAt),
    storeIds: user.storeAccesses.map((access) => access.storeId),
  };
}

async function writeAuthAudit(
  action: AuditAction,
  context: AuthContextInput,
  userId?: string | null,
  metadata?: Prisma.InputJsonObject
) {
  await writeAuditLog({
    action,
    userId,
    ipAddress: context.ipAddress,
    userAgent: context.userAgent,
    metadata,
  });
}

async function createAuthToken(
  userId: string,
  purpose: AuthTokenPurpose
) {
  const token = generateRandomToken();

  await prisma.authToken.create({
    data: {
      tokenHash: await hashToken(token),
      purpose,
      userId,
      expiresAt: new Date(Date.now() + AUTH_TOKEN_DURATION_MS),
    },
  });

  return token;
}

async function consumeAuthToken(
  token: string,
  purpose: AuthTokenPurpose,
  errorCode:
    | "AUTH_INVALID_RESET_TOKEN"
    | "AUTH_INVALID_VERIFICATION_TOKEN"
) {
  const tokenHash = await hashToken(token);
  const authToken = await prisma.authToken.findUnique({
    where: {
      tokenHash,
    },
  });

  if (
    !authToken ||
    authToken.purpose !== purpose ||
    authToken.usedAt ||
    authToken.expiresAt <= new Date()
  ) {
    throw new AuthError(errorCode, "Invalid or expired token");
  }

  await prisma.authToken.update({
    where: {
      id: authToken.id,
    },
    data: {
      usedAt: new Date(),
    },
  });

  return authToken;
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

export async function registerUser(
  data: RegisterInput,
  context: AuthContextInput = {}
) {
  const email = data.email.trim().toLowerCase();

  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new AuthError(
      "AUTH_EMAIL_ALREADY_EXISTS",
      "Email already exists",
      409
    );
  }

  if (data.storeId) {
    const store = await prisma.store.findUnique({
      where: { id: data.storeId },
      select: { id: true },
    });

    if (!store) {
      throw new AuthError(
        "VALIDATION_FAILED",
        "Store does not exist",
        400
      );
    }
  }

  const hashedPassword = await hashPassword(data.password);

  const user = await prisma.user.create({
    data: {
      firstName: data.firstName.trim(),
      lastName: data.lastName.trim(),
      email,
      password: hashedPassword,
      role: "EMPLOYEE",
      storeAccesses: data.storeId
        ? {
            create: {
              storeId: data.storeId,
            },
          }
        : undefined,
    },
    include: {
      storeAccesses: {
        select: { storeId: true },
      },
    },
  });

  const emailVerificationToken = await createAuthToken(
    user.id,
    "EMAIL_VERIFICATION"
  );

  await sendEmailVerification(user.email, emailVerificationToken);

  await writeAuthAudit("REGISTER", context, user.id);

  return {
    user: toPublicUser(user),
    emailVerificationToken,
  };
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
        select: { storeId: true },
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
  const refreshTokenHash = await hashToken(refreshToken);
  const matchedToken = await prisma.refreshToken.findUnique({
    where: {
      tokenHash: refreshTokenHash,
    },
    include: {
      session: {
        include: {
          user: {
            include: {
              storeAccesses: {
                select: {
                  storeId: true,
                },
              },
            },
          },
        },
      },
    },
  });

  if (!matchedToken) {
    throw new AuthError(
      "AUTH_INVALID_REFRESH_TOKEN",
      "Invalid refresh token"
    );
  }

  if (matchedToken.revokedAt) {
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

  const now = new Date();

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
      },
    });

    if (updatedToken.count !== 1) {
      return null;
    }

    return tx.session.update({
      where: {
        id: matchedToken.sessionId,
      },
      data: {
        expiresAt: newRefreshToken.record.expiresAt,
        refreshTokens: {
          create: newRefreshToken.record,
        },
      },
    });
  });

  if (!session) {
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
  const refreshTokenHash = await hashToken(refreshToken);
  const matchedToken = await prisma.refreshToken.findUnique({
    where: {
      tokenHash: refreshTokenHash,
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

export async function verifyEmail(data: VerifyEmailInput) {
  const authToken = await consumeAuthToken(
    data.token,
    "EMAIL_VERIFICATION",
    "AUTH_INVALID_VERIFICATION_TOKEN"
  );

  await prisma.user.update({
    where: {
      id: authToken.userId,
    },
    data: {
      emailVerifiedAt: new Date(),
    },
  });
}

export async function requestPasswordReset(
  data: RequestPasswordResetInput
) {
  const user = await prisma.user.findUnique({
    where: {
      email: data.email.trim().toLowerCase(),
    },
    select: {
      id: true,
      isActive: true,
    },
  });

  if (!user || !user.isActive) {
    return {
      resetToken: null,
    };
  }

  const resetToken = await createAuthToken(
    user.id,
    "PASSWORD_RESET"
  );

  await sendPasswordReset(data.email, resetToken);

  return {
    resetToken,
  };
}

export async function resetPassword(data: ResetPasswordInput) {
  const authToken = await consumeAuthToken(
    data.token,
    "PASSWORD_RESET",
    "AUTH_INVALID_RESET_TOKEN"
  );

  const password = await hashPassword(data.password);

  await prisma.$transaction(async (tx) => {
    await tx.user.update({
      where: {
        id: authToken.userId,
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
          userId: authToken.userId,
        },
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  });
}

export async function changePassword(
  userId: string,
  data: ChangePasswordInput
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

  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      password: await hashPassword(data.newPassword),
    },
  });
}
