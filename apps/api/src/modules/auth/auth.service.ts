import { prisma } from "../../lib/prisma";

import type {
  RegisterInput,
} from "./auth.schema";

import {
  hashPassword,
} from "../../utils/hash";

export async function registerUser(
  data: RegisterInput
) {
  const email =
    data.email
      .trim()
      .toLowerCase();

  const existing =
    await prisma.user.findUnique({
      where: {
        email,
      },
    });

  if (existing) {
    throw new Error(
      "AUTH_EMAIL_ALREADY_EXISTS"
    );
  }

  const hashedPassword =
    await hashPassword(
      data.password
    );

  const user =
    await prisma.user.create({
      data: {
        firstName:
          data.firstName.trim(),

        lastName:
          data.lastName.trim(),

        email,

        password:
          hashedPassword,

        role:
          "EMPLOYEE",
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

  return user;
}