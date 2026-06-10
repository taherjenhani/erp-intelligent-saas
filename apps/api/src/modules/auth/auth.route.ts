import type { FastifyInstance, FastifyRequest } from "fastify";

import { env } from "../../config/env";
import { requireAuth } from "../../middlewares/auth.middleware";
import {
  changePasswordController,
  csrfTokenController,
  logoutAllController,
  loginController,
  logoutController,
  meController,
  refreshController,
  registerController,
  resendEmailVerificationController,
  requestPasswordResetController,
  resetPasswordController,
  verifyEmailController,
} from "./auth.controller";

export async function authRoutes(app: FastifyInstance) {
  const csrf = app.csrfProtection;
  const identityKey = (request: FastifyRequest) => {
    const body = request.body as { email?: unknown } | undefined;
    const email =
      typeof body?.email === "string"
        ? body.email.trim().toLowerCase()
        : "unknown";

    return `${request.ip}:${email}`;
  };
  const authRateLimit = () => app.rateLimit({
    max: env.AUTH_RATE_LIMIT_MAX,
    timeWindow: env.AUTH_RATE_LIMIT_WINDOW,
    keyGenerator: identityKey,
  });

  app.get("/csrf-token", csrfTokenController);
  app.post(
    "/register",
    {
      preHandler: authRateLimit(),
      preValidation: csrf,
    },
    registerController
  );
  app.post(
    "/verify-email",
    {
      preHandler: authRateLimit(),
      preValidation: csrf,
    },
    verifyEmailController
  );
  app.post(
    "/resend-verification",
    {
      preHandler: authRateLimit(),
      preValidation: csrf,
    },
    resendEmailVerificationController
  );
  app.post(
    "/forgot-password",
    {
      preHandler: authRateLimit(),
      preValidation: csrf,
    },
    requestPasswordResetController
  );
  app.post(
    "/reset-password",
    {
      preHandler: authRateLimit(),
      preValidation: csrf,
    },
    resetPasswordController
  );

  app.post(
    "/login",
    {
      preHandler: app.rateLimit({
        max: env.LOGIN_RATE_LIMIT_MAX,
        timeWindow: env.LOGIN_RATE_LIMIT_WINDOW,
        keyGenerator: identityKey,
      }),
      preValidation: csrf,
    },
    loginController
  );

  app.post(
    "/refresh",
    {
      preHandler: app.rateLimit({
        max: env.AUTH_RATE_LIMIT_MAX,
        timeWindow: env.AUTH_RATE_LIMIT_WINDOW,
        keyGenerator: (request) => request.ip,
      }),
      preValidation: csrf,
    },
    refreshController
  );

  app.post(
    "/logout",
    {
      preValidation: csrf,
    },
    logoutController
  );

  app.post(
    "/logout-all",
    {
      preHandler: requireAuth,
      preValidation: csrf,
    },
    logoutAllController
  );

  app.post(
    "/change-password",
    {
      preHandler: requireAuth,
      preValidation: csrf,
    },
    changePasswordController
  );

  app.get("/me", { preHandler: requireAuth }, meController);
}
