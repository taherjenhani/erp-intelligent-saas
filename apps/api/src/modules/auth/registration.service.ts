import { Prisma } from "@prisma/client";

import {
  buildEmailVerificationMessage,
  enqueueEmail,
  processQueuedEmail,
} from "../../lib/email";
import { AuthError } from "../../lib/errors";
import { reportOperationalError } from "../../lib/operationalErrors";
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

  const hashedPasswordPromise = hashPassword(data.password);
  const existingUser = await findUserByEmail(email);
  const hashedPassword = await hashedPasswordPromise;

  if (existingUser) {
    return {
      user: null,
      emailVerificationToken: null,
      created: false,
    };
  }

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
      return {
        user: null,
        emailVerificationToken: null,
        created: false,
      };
    }

    throw error;
  }

  const {
    user,
    emailVerificationToken,
    emailVerificationOutboxId,
  } = result;

  void processQueuedEmail(emailVerificationOutboxId).catch((error) => {
    reportOperationalError("inline_email_processing_failed", error, {
      outboxId: emailVerificationOutboxId,
      userId: user.id,
      purpose: "email_verification",
    });
  });

  await writeAuthAudit("REGISTER", context, user.id);

  return {
    user: toPublicUser(user),
    emailVerificationToken,
    created: true,
  };
}
