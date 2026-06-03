import { buildApp } from "./app";
import { env } from "./config/env";
import { prisma } from "./lib/prisma";

const start = async () => {
  const app = buildApp();

  const shutdown = async () => {
    await app.close();
    await prisma.$disconnect();
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  try {
    await app.listen({
      port: env.PORT,
      host: "0.0.0.0",
    });

    console.log(`Server running on http://localhost:${env.PORT}`);
  } catch (err) {
    app.log.error(err);
    await shutdown();
    process.exit(1);
  }
};

start();
