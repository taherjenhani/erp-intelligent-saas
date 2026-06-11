import csrfProtection from "@fastify/csrf-protection";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";
import Redis from "ioredis";

import { env } from "../config/env";

const allowedOrigins = env.CORS_ORIGIN.split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const securityPlugin: FastifyPluginAsync = async (app) => {
  const redis = env.RATE_LIMIT_REDIS_URL
    ? new Redis(env.RATE_LIMIT_REDIS_URL, {
        keyPrefix: "erp-api:rate-limit:",
        enableOfflineQueue: false,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
      })
    : undefined;

  if (redis) {
    try {
      await redis.connect();
      await redis.ping();
    } catch (error) {
      redis.disconnect();
      app.log.error(error, "Redis rate-limit store is unavailable");
      throw error;
    }

    app.addHook("onClose", async () => {
      redis.disconnect();
    });
  }

  await app.register(helmet, {
    contentSecurityPolicy: env.HELMET_CSP_ENABLED
      ? undefined
      : false,
  });

  await app.register(cors, {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error("CORS origin not allowed"), false);
    },
    credentials: true,
  });

  await app.register(rateLimit, {
    global: false,
    max: 100,
    timeWindow: "1 minute",
    redis,
  });

  await app.register(csrfProtection, {
    sessionPlugin: "@fastify/cookie",
    cookieKey: "csrfSecret",
    cookieOpts: {
      httpOnly: true,
      secure: env.NODE_ENV === "production",
      sameSite: "strict",
      domain: env.COOKIE_DOMAIN,
      path: "/",
    },
    csrfOpts: {
      hmacKey: env.CSRF_SECRET,
    },
    getToken: (request) =>
      request.headers["x-csrf-token"]?.toString(),
  });
};

export default fp(securityPlugin);
