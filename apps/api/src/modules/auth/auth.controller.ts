import {
  FastifyReply,
  FastifyRequest,
} from "fastify";

import {
  registerSchema,
} from "./auth.schema";

import {
  registerUser,
} from "./auth.service";

export async function registerController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const data =
    registerSchema.parse(
      request.body
    );

  const user =
    await registerUser(
      data
    );

  return reply
    .status(201)
    .send({
      success: true,

      message:
        "User created successfully",

      data: user,
    });
}