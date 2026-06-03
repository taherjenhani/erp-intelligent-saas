import { FastifyReply, FastifyRequest } from "fastify";
import { Role } from "@prisma/client";

export function requireRole(roles: Role[]) {
  return async function (
    request: FastifyRequest,
    reply: FastifyReply
  ) {
    if (!request.auth) {
      return reply.status(401).send({
        success: false,
        message: "Unauthorized",
      });
    }

    if (!roles.includes(request.auth.role)) {
      return reply.status(403).send({
        success: false,
        message: "Forbidden",
      });
    }
  };
}