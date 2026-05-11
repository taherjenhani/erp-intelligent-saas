import Fastify from "fastify";

console.log("APP FILE LOADED ✅");

export function buildApp() {
  const app = Fastify({ logger: true });

  app.get("/", async () => ({ ok: true, route: "/" }));
  app.get("/api", async () => ({ ok: true, route: "/api" }));
  app.get("/__ping__", async () => ({ ok: true }));

  return app;
}