import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

const CORRELATION_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

function sanitizeCorrelationId(value: unknown) {
  const candidate = Array.isArray(value) ? value[0] : value;

  if (
    typeof candidate === "string" &&
    CORRELATION_ID_PATTERN.test(candidate)
  ) {
    return candidate;
  }

  return null;
}

const requestContextPlugin: FastifyPluginAsync = async (app) => {
  app.addHook("onRequest", async (request, reply) => {
    const correlationId =
      sanitizeCorrelationId(request.headers["x-correlation-id"]) ??
      sanitizeCorrelationId(request.headers["x-request-id"]);

    request.correlationId = correlationId || request.id;

    reply.header("x-request-id", request.id);
    reply.header("x-correlation-id", request.correlationId);
  });
};

export default fp(requestContextPlugin);
