import Fastify from "fastify";

import jwtPlugin from "./plugins/jwt";

import {
  authRoutes,
} from "./modules/auth/auth.route";

export function buildApp() {
  const app =
    Fastify({
      logger: true,
    });

  app.register(
    jwtPlugin
  );

  app.register(
    authRoutes,
    {
      prefix:
        "/api/auth",
    }
  );

  app.get(
    "/",
    async () => ({
      message:
        "ERP API running 🚀",
    })
  );

  return app;
}