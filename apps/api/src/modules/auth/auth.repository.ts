import { Prisma } from "@prisma/client";

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
  },
  client: PrismaClientLike = prisma
) {
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
      revokedAt: new Date(),
    },
  });
}

export function createSessionWithRefreshToken(
  input: {
    userId: string;
    userAgent?: string | null;
    ipAddress?: string | null;
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
  },
  client: PrismaClientLike = prisma
) {
  await client.refreshToken.updateMany({
    where: {
      familyId: input.familyId,
      revokedAt: null,
    },
    data: {
      revokedAt: new Date(),
    },
  });

  await client.session.update({
    where: {
      id: input.sessionId,
    },
    data: {
      status: "REVOKED",
    },
  });
}

export async function revokeSessionByRefreshToken(
  input: {
    refreshTokenId: string;
    sessionId: string;
  },
  client: PrismaClientLike = prisma
) {
  await client.refreshToken.update({
    where: {
      id: input.refreshTokenId,
    },
    data: {
      revokedAt: new Date(),
    },
  });

  await client.session.update({
    where: {
      id: input.sessionId,
    },
    data: {
      status: "REVOKED",
    },
  });
}

export async function revokeAllActiveUserSessionsAndTokens(
  userId: string,
  client: PrismaClientLike = prisma
) {
  await client.session.updateMany({
    where: {
      userId,
      status: "ACTIVE",
    },
    data: {
      status: "REVOKED",
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
      revokedAt: new Date(),
    },
  });
}
