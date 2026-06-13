import Fastify from "fastify";
import crypto from "crypto";

import { env } from "./config/env";
import { authRoutes } from "./modules/auth/auth.route";
import emailOutboxWorkerPlugin from "./plugins/emailOutboxWorker";
import errorHandlerPlugin from "./plugins/errorHandler";
import jwtPlugin from "./plugins/jwt";
import metricsPlugin from "./plugins/metrics";
import requestContextPlugin from "./plugins/requestContext";
import securityPlugin from "./plugins/security";
import tokenCleanupWorkerPlugin from "./plugins/tokenCleanupWorker";

export function buildApp() {
  const app = Fastify({
    logger: {
      level: env.NODE_ENV === "production" ? "info" : "debug",
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "req.headers['set-cookie']",
          "req.body.password",
          "req.body.newPassword",
          "req.body.confirmPassword",
          "req.body.token",
          "req.body.refreshToken",
        ],
      },
    },
    requestIdHeader: false,
    genReqId: () => crypto.randomUUID(),
    trustProxy: env.TRUST_PROXY,
  });

  app.register(requestContextPlugin);
  app.register(jwtPlugin);
  app.register(securityPlugin);
  app.register(emailOutboxWorkerPlugin);
  app.register(tokenCleanupWorkerPlugin);
  app.register(errorHandlerPlugin);
  app.register(metricsPlugin);

  app.register(authRoutes, {
    prefix: "/api/auth",
  });

  app.get("/", async () => ({
    message: "ERP API running",
  }));

  return app;
}
