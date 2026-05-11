import Fastify from "fastify";

export function buildApp() {
  const app = Fastify({
    logger: true,
  });

  app.get("/", async () => ({
    message: "ERP API running 🚀",
  }));

  app.get("/__ping__", async () => ({
    ok: true,
  }));

  return app;
}