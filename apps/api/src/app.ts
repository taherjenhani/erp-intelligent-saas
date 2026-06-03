import Fastify from "fastify";

import { authRoutes } from "./modules/auth/auth.route";
import errorHandlerPlugin from "./plugins/errorHandler";
import jwtPlugin from "./plugins/jwt";
import securityPlugin from "./plugins/security";

export function buildApp() {
  const app = Fastify({
    logger: true,
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
