import csrfProtection from "@fastify/csrf-protection";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

import { env } from "../config/env";

const securityPlugin: FastifyPluginAsync = async (app) => {
  await app.register(cors, {
    origin: env.CORS_ORIGIN,
    credentials: true,
  });

  await app.register(rateLimit, {
    global: false,
    max: 100,
    timeWindow: "1 minute",
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
