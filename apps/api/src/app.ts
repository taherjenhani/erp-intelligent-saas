import Fastify from "fastify";

import { env } from "./config/env";
import { authRoutes } from "./modules/auth/auth.route";
import errorHandlerPlugin from "./plugins/errorHandler";
import jwtPlugin from "./plugins/jwt";
import securityPlugin from "./plugins/security";

export function buildApp() {
  const app = Fastify({
    logger: true,
    trustProxy: env.TRUST_PROXY,
  });

  app.register(jwtPlugin);
  app.register(securityPlugin);
  app.register(errorHandlerPlugin);

  app.register(authRoutes, {
    prefix: "/api/auth",
  });

  app.get("/", async () => ({
    message: "ERP API running",
  }));

  return app;
}
