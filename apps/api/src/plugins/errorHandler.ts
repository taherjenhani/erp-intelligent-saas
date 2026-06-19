import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import { ZodError } from "zod";

import { AppError } from "../lib/errors";

function serializeError(error: unknown) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }

  return { message: String(error) };
}

const errorHandlerPlugin: FastifyPluginAsync = async (app) => {
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ZodError) {
      return reply.status(400).send({
        success: false,
        code: "VALIDATION_FAILED",
        message: "Validation failed",
        correlationId: request.correlationId,
        errors: error.issues,
      });
    }

    if (error instanceof AppError) {
      return reply.status(error.statusCode).send({
        success: false,
        code: error.code,
        message: error.message,
        correlationId: request.correlationId,
      });
    }

    if (
      typeof error === "object" &&
      error !== null &&
      "statusCode" in error &&
      typeof error.statusCode === "number" &&
      error.statusCode >= 400 &&
      error.statusCode < 500
    ) {
      const statusCode = error.statusCode;
      const message =
        error instanceof Error ? error.message : "Request failed";
      const normalizedMessage = message.toLowerCase();
      const code =
        statusCode === 429
          ? "RATE_LIMIT_EXCEEDED"
          : statusCode === 403 && normalizedMessage.includes("csrf")
            ? "CSRF_INVALID"
            : "REQUEST_FAILED";

      return reply.status(statusCode).send({
        success: false,
        code,
        message:
          statusCode === 429
            ? "Too many requests, please try again later"
            : message,
        correlationId: request.correlationId,
      });
    }

    app.log.error(
      {
        correlationId: request.correlationId,
        error: serializeError(error),
      },
      "Unhandled error"
    );

    return reply.status(500).send({
      success: false,
      code: "INTERNAL_SERVER_ERROR",
      message: "Internal server error",
      correlationId: request.correlationId,
    });
  });
};

export default fp(errorHandlerPlugin);
