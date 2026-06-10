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

export function findUserByEmail(email: string, client: PrismaClientLike = prisma) {
  return client.user.findUnique({
    where: { email },
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
    },
  });
}

export function createRegisteredUser(
  input: {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
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
