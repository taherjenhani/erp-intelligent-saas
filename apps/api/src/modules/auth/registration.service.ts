import { Prisma } from "@prisma/client";

import {
  buildEmailVerificationMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { prisma } from "../../lib/prisma";
import {
  activePasswordPepperKeyId,
  hashPassword,
} from "../../utils/hash";
import { writeAuthAudit } from "./auth-audit.service";
import { toPublicUser } from "./auth.mapper";
import {
  createRegisteredUser,
  findActiveStoreForRegistration,
  findUserByEmail,
} from "./auth.repository";
import { createAuthToken } from "./auth-token.service";
import type { RegisterInput } from "./auth.schema";
import type { AuthContextInput, PublicUserRecord } from "./auth.types";
import { rememberPassword } from "./password-history.service";

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

  const existingUser = await findUserByEmail(email);

  if (existingUser) {
    throw new AuthError(
      "AUTH_EMAIL_ALREADY_EXISTS",
      "Email already exists",
      409
    );
  }

  let storeOrganizationId: string | null = null;

  if (data.storeId) {
    const store = await findActiveStoreForRegistration(data.storeId);

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
      const createdUser = await createRegisteredUser({
        firstName: data.firstName.trim(),
        lastName: data.lastName.trim(),
        email,
        password: hashedPassword,
        passwordPepperKeyId: activePasswordPepperKeyId(),
        storeId: data.storeId,
        organizationId: storeOrganizationId,
      }, tx);

      await rememberPassword(
        createdUser.id,
        hashedPassword,
        tx
      );

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
