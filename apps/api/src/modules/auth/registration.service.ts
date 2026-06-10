import { Prisma } from "@prisma/client";

import {
  buildEmailVerificationMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import { hashPassword } from "../../utils/hash";
import { writeAuthAudit } from "./auth-audit.service";
import { toPublicUser } from "./auth.mapper";
import { createAuthToken } from "./auth-token.service";
import type { RegisterInput } from "./auth.schema";
import type { AuthContextInput, PublicUserRecord } from "./auth.types";

function isUniqueConstraintError(error: unknown) {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === "P2002"
  );
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

  let storeOrganizationId: string | null = null;

  if (data.storeId) {
    const store = await prisma.store.findFirst({
      where: {
        id: data.storeId,
        isActive: true,
        organization: {
          isActive: true,
        },
      },
      select: { id: true, organizationId: true },
    });

    if (!store) {
      throw new AuthError(
        "VALIDATION_FAILED",
        "Store does not exist or is inactive",
        400
      );
    }

    storeOrganizationId = store.organizationId;
  }

  const hashedPassword = await hashPassword(data.password);

  let result: {
    user: PublicUserRecord;
    emailVerificationToken: string;
    emailVerificationOutboxId: string;
  };

  try {
    result = await prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
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
                  role: "EMPLOYEE",
                },
              }
            : undefined,
          memberships: storeOrganizationId
            ? {
                create: {
                  organizationId: storeOrganizationId,
                  role: "EMPLOYEE",
                },
              }
            : undefined,
        },
        include: {
          storeAccesses: {
            select: { storeId: true, role: true },
          },
          memberships: {
            select: { organizationId: true, role: true },
          },
        },
      });

      const emailVerificationToken = await createAuthToken(
        createdUser.id,
        "EMAIL_VERIFICATION",
        tx
      );
      const queuedEmail = await enqueueEmail(
        tx,
        buildEmailVerificationMessage(
          createdUser.email,
          emailVerificationToken
        )
      );

      return {
        user: createdUser,
        emailVerificationToken,
        emailVerificationOutboxId: queuedEmail.id,
      };
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw new AuthError(
        "AUTH_EMAIL_ALREADY_EXISTS",
        "Email already exists",
        409
      );
    }

    throw error;
  }

  const {
    user,
    emailVerificationToken,
    emailVerificationOutboxId,
  } = result;

  void processQueuedEmail(emailVerificationOutboxId).catch((error) => {
    console.error("Inline email processing failed", error);
  });

  await writeAuthAudit("REGISTER", context, user.id);

  return {
    user: toPublicUser(user),
    emailVerificationToken,
  };
}
