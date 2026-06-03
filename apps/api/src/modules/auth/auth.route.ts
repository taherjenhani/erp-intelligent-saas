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

  app.get("/csrf-token", csrfTokenController);
  app.post("/register", registerController);
  app.post("/verify-email", verifyEmailController);
  app.post("/forgot-password", requestPasswordResetController);
  app.post("/reset-password", resetPasswordController);

  app.post(
    "/login",
    {
      preHandler: app.rateLimit({
        max: env.LOGIN_RATE_LIMIT_MAX,
        timeWindow: env.LOGIN_RATE_LIMIT_WINDOW,
      }),
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
