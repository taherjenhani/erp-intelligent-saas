import Fastify from "fastify";
import jwtPlugin from "./plugins/jwt";

export function buildApp() {
  const app = Fastify({
    logger: true,
  });

  app.register(jwtPlugin);

  app.get("/", async () => ({
    message: "ERP API running 🚀",
  }));

  app.get("/__ping__", async () => ({
    ok: true,
  }));

  return app;
}