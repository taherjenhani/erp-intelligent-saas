import type { FastifyInstance } from "fastify";

import { env } from "../../config/env";
import { requireAuth } from "../../middlewares/auth.middleware";
import {
  changePasswordController,
  csrfTokenController,
  loginController,
  logoutController,
  meController,
  refreshController,
  registerController,
  requestPasswordResetController,
  resetPasswordController,
  verifyEmailController,
} from "./auth.controller";

export async function authRoutes(app: FastifyInstance) {
  const csrf = app.csrfProtection;
  const authRateLimit = () => app.rateLimit({
    max: env.AUTH_RATE_LIMIT_MAX,
    timeWindow: env.AUTH_RATE_LIMIT_WINDOW,
  });

  app.get("/csrf-token", csrfTokenController);
  app.post(
    "/register",
    { preValidation: csrf },
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
      }),
      preValidation: csrf,
    },
    loginController
  );

  app.post(
    "/refresh",
    {
      preValidation: csrf,
    },
    refreshController
  );

  app.post(
    "/logout",
    {
      preHandler: requireAuth,
      preValidation: csrf,
    },
    logoutController
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
