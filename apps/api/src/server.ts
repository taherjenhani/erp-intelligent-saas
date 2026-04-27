import Fastify from "fastify";

const app = Fastify({ logger: true });

app.get("/health", async () => {
  return { status: "ok" };
});

app.listen({ port: 5000, host: "0.0.0.0" });