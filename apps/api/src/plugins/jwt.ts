import fp from "fastify-plugin";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { env } from "../config/env";

export default fp(async (app) => {
  await app.register(cookie);

  await app.register(jwt, {
    secret: env.JWT_ACCESS_SECRET,
    sign: {
      algorithm: "HS256",
    },
    verify: {
      algorithms: ["HS256"],
    },
  });
});
