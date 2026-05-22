import {
  FastifyInstance,
} from "fastify";

import {
  registerController,
} from "./auth.controller";

export async function authRoutes(
  app: FastifyInstance
) {
  app.post(
    "/register",
    registerController
  );
}