import "@fastify/jwt";
import { AccessTokenPayload, RefreshTokenPayload } from "./auth";

declare module "fastify" {
  interface FastifyInstance {
    signAccessToken: (payload: AccessTokenPayload) => string;
    verifyAccessToken: (token: string) => AccessTokenPayload;

    signRefreshToken: (payload: RefreshTokenPayload) => string;
    verifyRefreshToken: (token: string) => RefreshTokenPayload;
  }
}