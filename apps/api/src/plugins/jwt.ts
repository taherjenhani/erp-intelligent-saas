import fp from "fastify-plugin";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { env } from "../config/env";

export default fp(async (app) => {
  await app.register(cookie);

  await app.register(jwt, {
    secret: env.JWT_ACCESS_SECRET,
    namespace: "access",
    jwtSign: "signAccessToken",
    jwtVerify: "verifyAccessToken",
  });

  await app.register(jwt, {
    secret: env.JWT_REFRESH_SECRET,
    namespace: "refresh",
    jwtSign: "signRefreshToken",
    jwtVerify: "verifyRefreshToken",
    cookie: {
      cookieName: "refreshToken",
      signed: false,
    },
  });
});