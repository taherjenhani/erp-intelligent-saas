import {
  Prisma,
  type SessionStatus,
  type SessionTerminationReason,
} from "@prisma/client";

import { prisma } from "../../lib/prisma";

export type PrismaClientLike = Prisma.TransactionClient | typeof prisma;

export const registeredUserInclude = {
  storeAccesses: {
    select: { storeId: true, role: true },
  },
  memberships: {
    select: { organizationId: true, role: true },
  },
} satisfies Prisma.UserInclude;

export const refreshTokenSessionInclude = {
  session: {
    include: {
      user: {
        include: registeredUserInclude,
      },
    },
  },
} satisfies Prisma.RefreshTokenInclude;

const logoutRefreshTokenInclude = {
  session: {
    select: {
      userId: true,
    },
  },
} satisfies Prisma.RefreshTokenInclude;

export type RefreshTokenWithSession = Prisma.RefreshTokenGetPayload<{
  include: typeof refreshTokenSessionInclude;
}>;

type SessionTerminationInput = {
  terminatedBy?: string | null;
  terminatedReason: SessionTerminationReason;
  sessionStatus?: SessionStatus;
};

export function findUserByEmail(email: string, client: PrismaClientLike = prisma) {
  return client.user.findUnique({
    where: { email },
  });
}

export function findLoginUserByEmail(
  email: string,
  client: PrismaClientLike = prisma
) {
  return client.user.findUnique({
    where: { email },
    include: registeredUserInclude,
  });
}

export function findActiveStoreForRegistration(
  storeId: string,
  client: PrismaClientLike = prisma
) {
  return client.store.findFirst({
    where: {
      id: storeId,
      isActive: true,
      organization: {
        isActive: true,
      },
    },
    select: { id: true, organizationId: true },
  });
}

export function findPasswordResetUser(
  email: string,
  client: PrismaClientLike = prisma
) {
  return client.user.findUnique({
    where: {
      email,
    },
    select: {
      id: true,
      email: true,
      isActive: true,
    },
  });
}

export function findUserPasswordById(
  userId: string,
  client: PrismaClientLike = prisma
) {
  return client.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      id: true,
      password: true,
      passwordPepperKeyId: true,
    },
  });
}

export function createRegisteredUser(
  input: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    passwordPepperKeyId?: string | null;
    storeId?: string;
    organizationId?: string | null;
  },
  client: PrismaClientLike = prisma
) {
  return client.user.create({
    data: {
      firstName: input.firstName,
      lastName: input.lastName,
      email: input.email,
      password: input.password,
      passwordPepperKeyId: input.passwordPepperKeyId,
      role: "EMPLOYEE",
      storeAccesses: input.storeId
        ? {
            create: {
              storeId: input.storeId,
              role: "EMPLOYEE",
            },
          }
        : undefined,
      memberships: input.organizationId
        ? {
            create: {
              organizationId: input.organizationId,
              role: "EMPLOYEE",
            },
          }
        : undefined,
    },
    include: registeredUserInclude,
  });
}

export async function updatePasswordAndRevokeOtherSessions(
  input: {
    userId: string;
    password: string;
    passwordPepperKeyId?: string | null;
    keepSessionId?: string;
    terminatedBy: string;
    terminatedReason: SessionTerminationReason;
  },
  client: PrismaClientLike = prisma
) {
  const revokedAt = new Date();

  await client.user.update({
    where: {
      id: input.userId,
    },
    data: {
      password: input.password,
      passwordPepperKeyId: input.passwordPepperKeyId,
    },
  });

  await client.session.updateMany({
    where: {
      userId: input.userId,
      id: input.keepSessionId
        ? {
            not: input.keepSessionId,
          }
        : undefined,
      status: "ACTIVE",
    },
    data: {
      status: "REVOKED",
      revokedAt,
      terminatedAt: revokedAt,
      terminatedBy: input.terminatedBy,
      terminatedReason: input.terminatedReason,
    },
  });

  await client.refreshToken.updateMany({
    where: {
      session: {
        userId: input.userId,
        id: input.keepSessionId
          ? {
              not: input.keepSessionId,
            }
          : undefined,
      },
      revokedAt: null,
    },
    data: {
      revokedAt,
    },
  });
}

export function updateUserPasswordHashIfCurrent(
  input: {
    userId: string;
    currentPasswordHash: string;
    password: string;
    passwordPepperKeyId: string;
  },
  client: PrismaClientLike = prisma
) {
  return client.user.updateMany({
    where: {
      id: input.userId,
      password: input.currentPasswordHash,
    },
    data: {
      password: input.password,
      passwordPepperKeyId: input.passwordPepperKeyId,
    },
  });
}

export function createSessionWithRefreshToken(
  input: {
    userId: string;
    userAgent?: string | null;
    ipAddress?: string | null;
    lastUsedAt?: Date;
    deviceName?: string | null;
    deviceFingerprintHash?: string | null;
    expiresAt: Date;
    refreshTokenRecord: Prisma.RefreshTokenCreateWithoutSessionInput;
  },
  client: PrismaClientLike = prisma
) {
  return client.session.create({
    data: {
      userId: input.userId,
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      lastUsedAt: input.lastUsedAt,
      deviceName: input.deviceName,
      deviceFingerprintHash: input.deviceFingerprintHash,
      expiresAt: input.expiresAt,
      refreshTokens: {
        create: input.refreshTokenRecord,
      },
    },
  });
}

export function findRefreshTokenByHashesWithSession(
  tokenHashes: string[],
  client: PrismaClientLike = prisma
) {
  return client.refreshToken.findFirst({
    where: {
      tokenHash: {
        in: tokenHashes,
      },
    },
    include: refreshTokenSessionInclude,
  });
}

export function findRefreshTokenByIdWithSession(
  tokenId: string,
  client: PrismaClientLike = prisma
) {
  return client.refreshToken.findUnique({
    where: {
      id: tokenId,
    },
    include: refreshTokenSessionInclude,
  });
}

export function findRefreshRotationReplay(
  input: {
    previousRefreshTokenId: string;
    idempotencyKeyHash: string;
    contextHash: string;
    now: Date;
  },
  client: PrismaClientLike = prisma
) {
  return client.refreshRotation.findFirst({
    where: {
      previousRefreshTokenId: input.previousRefreshTokenId,
      idempotencyKeyHash: input.idempotencyKeyHash,
      contextHash: input.contextHash,
      idempotencyExpiresAt: {
        gt: input.now,
      },
      responseRefreshToken: {
        not: null,
      },
    },
  });
}

export function findLogoutRefreshTokenByHashes(
  tokenHashes: string[],
  client: PrismaClientLike = prisma
) {
  return client.refreshToken.findFirst({
    where: {
      tokenHash: {
        in: tokenHashes,
      },
    },
    include: logoutRefreshTokenInclude,
  });
}

export async function revokeRefreshTokenFamilyAndSession(
  input: {
    familyId: string;
    sessionId: string;
  } & SessionTerminationInput,
  client: PrismaClientLike = prisma
) {
  const revokedAt = new Date();

  await client.refreshToken.updateMany({
    where: {
      familyId: input.familyId,
      revokedAt: null,
    },
    data: {
      revokedAt,
    },
  });

  await client.session.update({
    where: {
      id: input.sessionId,
    },
    data: {
      status: input.sessionStatus ?? "REVOKED",
      revokedAt:
        input.sessionStatus === "EXPIRED" ? undefined : revokedAt,
      terminatedAt: revokedAt,
      terminatedBy: input.terminatedBy,
      terminatedReason: input.terminatedReason,
    },
  });
}

export async function revokeSessionByRefreshToken(
  input: {
    refreshTokenId: string;
    sessionId: string;
  } & SessionTerminationInput,
  client: PrismaClientLike = prisma
) {
  const revokedAt = new Date();

  await client.refreshToken.update({
    where: {
      id: input.refreshTokenId,
    },
    data: {
      revokedAt,
    },
  });

  await client.session.update({
    where: {
      id: input.sessionId,
    },
    data: {
      status: "REVOKED",
      revokedAt,
      terminatedAt: revokedAt,
      terminatedBy: input.terminatedBy,
      terminatedReason: input.terminatedReason,
    },
  });
}

export async function revokeAllActiveUserSessionsAndTokens(
  userId: string,
  client: PrismaClientLike = prisma,
  options: SessionTerminationInput = {
    terminatedBy: userId,
    terminatedReason: "LOGOUT_ALL",
  }
) {
  const revokedAt = new Date();

  await client.session.updateMany({
    where: {
      userId,
      status: "ACTIVE",
    },
    data: {
      status: "REVOKED",
      revokedAt,
      terminatedAt: revokedAt,
      terminatedBy: options.terminatedBy,
      terminatedReason: options.terminatedReason,
    },
  });

  await client.refreshToken.updateMany({
    where: {
      session: {
        userId,
      },
      revokedAt: null,
    },
    data: {
      revokedAt,
    },
  });
}
