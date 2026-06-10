import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

import { env } from "../config/env";
import { processEmailOutbox } from "../lib/email";

const emailOutboxWorkerPlugin: FastifyPluginAsync = async (app) => {
  if (!env.EMAIL_OUTBOX_WORKER_ENABLED) {
    return;
  }

  let isRunning = false;

  const runOnce = async () => {
    if (isRunning) {
      return;
    }

    isRunning = true;

    try {
      const processed = await processEmailOutbox();

      if (processed > 0) {
        app.log.info({ processed }, "Processed queued emails");
      }
    } catch (error) {
      app.log.error(error, "Email outbox worker failed");
    } finally {
      isRunning = false;
    }
  };

  const interval = setInterval(
    () => void runOnce(),
    env.EMAIL_OUTBOX_WORKER_INTERVAL_MS
  );

  void runOnce();

  app.addHook("onClose", async () => {
    clearInterval(interval);
  });
};

export default fp(emailOutboxWorkerPlugin);
