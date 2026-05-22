import { prisma } from "../../lib/prisma";

import { RegisterInput } from "./auth.schema";

import { hashPassword } from "../../utils/hash";

export async function registerUser(data: RegisterInput) {
  const existingUser =
    await prisma.user.findUnique({
      where: {
        email: data.email,
      },
    });

  if (existingUser) {
    throw new Error(
      "EMAIL_ALREADY_EXISTS"
    );
  }

  const password =
    await hashPassword(
      data.password
    );

  const user =
    await prisma.user.create({
      data: {
        firstName:
          data.firstName,

        lastName:
          data.lastName,

        email:
          data.email,

        password,

        role:
          "EMPLOYEE",
      },

      select: {
        id: true,

        firstName: true,

        lastName: true,

        email: true,

        role: true,

        createdAt: true,
      },
    });

  return user;
}