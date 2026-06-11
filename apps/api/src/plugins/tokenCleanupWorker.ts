import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

import { env } from "../config/env";
import { cleanupExpiredTokens } from "../jobs/cleanupTokens";

const tokenCleanupWorkerPlugin: FastifyPluginAsync = async (app) => {
  if (!env.TOKEN_CLEANUP_WORKER_ENABLED) {
    return;
  }

  let isRunning = false;

  const runOnce = async () => {
    if (isRunning) {
      return;
    }

    isRunning = true;

    try {
      const result = await cleanupExpiredTokens();
      app.log.info(result, "Cleaned expired auth records");
    } catch (error) {
      app.log.error(error, "Token cleanup worker failed");
    } finally {
      isRunning = false;
    }
  };

  const interval = setInterval(
    () => void runOnce(),
    env.TOKEN_CLEANUP_WORKER_INTERVAL_MS
  );

  void runOnce();

  app.addHook("onClose", async () => {
    clearInterval(interval);
  });
};

export default fp(tokenCleanupWorkerPlugin);
