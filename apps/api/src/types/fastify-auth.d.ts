import { AuthContext } from "../middlewares/auth.middleware";

declare module "fastify" {
  interface FastifyRequest {
    auth?: AuthContext;
    correlationId: string;
  }
}
