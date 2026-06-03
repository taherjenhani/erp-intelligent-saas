import { prisma } from "../../lib/prisma";
import type { RegisterInput } from "./auth.schema";
import { hashPassword, verifyPassword } from "../../utils/hash";
import {
  generateFamilyId,
  generateRandomToken,
  hashToken,verifyToken,
} from "../../utils/token";


const SESSION_DURATION_DAYS = 7;
const SESSION_DURATION_MS =
  SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000;

export async function registerUser(data: RegisterInput) {
  const email = data.email.trim().toLowerCase();

  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new Error("AUTH_EMAIL_ALREADY_EXISTS");
  }

  const hashedPassword = await hashPassword(data.password);

  return prisma.user.create({
    data: {
      firstName: data.firstName.trim(),
      lastName: data.lastName.trim(),
      email,
      password: hashedPassword,
      role: "EMPLOYEE",
    },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      role: true,
      isActive: true,
      createdAt: true,
    },
  });
}

export async function loginUser(email: string, password: string) {
  const normalizedEmail = email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    include: {
      storeAccesses: {
        select: { storeId: true },
      },
    },
  });

  if (!user) {
    throw new Error("AUTH_INVALID_CREDENTIALS");
  }

  if (!user.isActive) {
    throw new Error("AUTH_ACCOUNT_DISABLED");
  }

  const isPasswordValid = await verifyPassword(
    password,
    user.password
  );

  if (!isPasswordValid) {
    throw new Error("AUTH_INVALID_CREDENTIALS");
  }

  const session = await prisma.session.create({
    data: {
      userId: user.id,
      expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
    },
  });

  const refreshToken = generateRandomToken();
  const familyId = generateFamilyId();
  const refreshTokenHash = await hashToken(refreshToken);

  await prisma.refreshToken.create({
    data: {
      tokenHash: refreshTokenHash,
      familyId,
      sessionId: session.id,
      expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
    },
  });

  return {
    refreshToken,
    session,
    user: {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      storeIds: user.storeAccesses.map((access) => access.storeId),
    },
  };
}
export async function refreshSession(refreshToken: string) {
  const tokens = await prisma.refreshToken.findMany({
    where: {
      revokedAt: null,
      expiresAt: {
        gt: new Date(),
      },
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

  let matchedToken = null;

  for (const token of tokens) {
    const isValid = await verifyToken(
      refreshToken,
      token.tokenHash
    );

    if (isValid) {
      matchedToken = token;
      break;
    }
  }

  if (!matchedToken) {
    throw new Error("AUTH_INVALID_REFRESH_TOKEN");
  }

  if (matchedToken.session.status !== "ACTIVE") {
    throw new Error("AUTH_SESSION_REVOKED");
  }

  if (!matchedToken.session.user.isActive) {
    throw new Error("AUTH_ACCOUNT_DISABLED");
  }

  await prisma.refreshToken.update({
    where: {
      id: matchedToken.id,
    },
    data: {
      revokedAt: new Date(),
    },
  });

  const newRefreshToken = generateRandomToken();
  const newRefreshTokenHash = await hashToken(newRefreshToken);

  await prisma.refreshToken.create({
    data: {
      tokenHash: newRefreshTokenHash,
      familyId: matchedToken.familyId,
      sessionId: matchedToken.sessionId,
      expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
    },
  });

  return {
    refreshToken: newRefreshToken,
    session: matchedToken.session,
    user: {
      id: matchedToken.session.user.id,
      firstName: matchedToken.session.user.firstName,
      lastName: matchedToken.session.user.lastName,
      email: matchedToken.session.user.email,
      role: matchedToken.session.user.role,
      storeIds: matchedToken.session.user.storeAccesses.map(
        (access) => access.storeId
      ),
    },
  };
}
export async function logoutUser(refreshToken: string) {
  const tokens = await prisma.refreshToken.findMany({
    where: {
      revokedAt: null,
    },
    include: {
      session: true,
    },
  });

  let matchedToken = null;

  for (const token of tokens) {
    const isValid = await verifyToken(
      refreshToken,
      token.tokenHash
    );

    if (isValid) {
      matchedToken = token;
      break;
    }
  }

  if (!matchedToken) {
    return;
  }

  await prisma.refreshToken.update({
    where: {
      id: matchedToken.id,
    },
    data: {
      revokedAt: new Date(),
    },
  });

  await prisma.session.update({
    where: {
      id: matchedToken.sessionId,
    },
    data: {
      status: "REVOKED",
    },
  });
}