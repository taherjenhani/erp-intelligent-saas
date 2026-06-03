// src/modules/auth/auth.route.ts
import { FastifyInstance } from "fastify";
import {
  registerController,
  loginController,
  refreshController,
  logoutController,
  meController,
} from "./auth.controller";
import { requireAuth } from "../../middlewares/auth.middleware";

export async function authRoutes(app: FastifyInstance) {
  app.post("/register", registerController);
  app.post("/login", loginController);
  app.post("/refresh", refreshController);
  app.post("/logout", logoutController);

  // Route protégée : nécessite un JWT d’accès valide + session ACTIVE
  app.get("/me", { preHandler: requireAuth }, meController);
}