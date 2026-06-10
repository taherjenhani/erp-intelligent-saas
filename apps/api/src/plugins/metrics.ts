import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import crypto from "crypto";

import { env } from "../config/env";
import { renderMetrics } from "../lib/metrics";

function hasValidMetricsToken(authorization: string | undefined) {
  const expected = `Bearer ${env.METRICS_TOKEN}`;

  if (!authorization) {
    return false;
  }

  const actual = Buffer.from(authorization);
  const expectedBuffer = Buffer.from(expected);

  return (
    actual.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actual, expectedBuffer)
  );
}

const metricsPlugin: FastifyPluginAsync = async (app) => {
  if (!env.METRICS_ENABLED) {
    return;
  }

  app.get("/metrics", async (request, reply) => {
    if (!env.METRICS_TOKEN) {
      throw new Error("METRICS_TOKEN is required when metrics are enabled");
    }

    if (!hasValidMetricsToken(request.headers.authorization)) {
      return reply.status(401).send({
        success: false,
        code: "AUTH_UNAUTHORIZED",
        message: "Unauthorized",
        correlationId: request.correlationId,
      });
    }

    return reply
      .type("text/plain; version=0.0.4; charset=utf-8")
      .send(renderMetrics());
  });
};

export default fp(metricsPlugin);
