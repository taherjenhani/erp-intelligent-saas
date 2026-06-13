import fp from "fastify-plugin";
import jwt from "@fastify/jwt";
import type { FastifyJWTOptions } from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { env } from "../config/env";

function buildJwtOptions(): FastifyJWTOptions {
  if (env.JWT_ALGORITHM === "RS256") {
    if (!env.JWT_PRIVATE_KEY || !env.JWT_PUBLIC_KEY) {
      throw new Error(
        "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required when JWT_ALGORITHM=RS256"
      );
    }

    return {
      secret: {
        private: env.JWT_PRIVATE_KEY,
        public: env.JWT_PUBLIC_KEY,
      },
      sign: {
        algorithm: "RS256",
      },
      verify: {
        algorithms: ["RS256"],
      },
    };
  }

  if (!env.JWT_ACCESS_SECRET) {
    throw new Error("JWT_ACCESS_SECRET is required when JWT_ALGORITHM=HS256");
  }

  return {
    secret: env.JWT_ACCESS_SECRET,
    sign: {
      algorithm: "HS256",
    },
    verify: {
      algorithms: ["HS256"],
    },
  };
}

export default fp(async (app) => {
  await app.register(cookie);

  await app.register(jwt, buildJwtOptions());
});
