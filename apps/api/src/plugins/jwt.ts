import fp from "fastify-plugin";
import jwt from "@fastify/jwt";
import type { FastifyJWTOptions } from "@fastify/jwt";
import cookie from "@fastify/cookie";
import { env } from "../config/env";

type DecodedJwtWithHeader = {
  header?: {
    alg?: unknown;
    kid?: unknown;
  };
};

function jwtPublicKeyring() {
  const keys = new Map<string, string>();

  if (env.JWT_KEY_ID && env.JWT_PUBLIC_KEY) {
    keys.set(env.JWT_KEY_ID, env.JWT_PUBLIC_KEY);
  }

  if (!env.JWT_PUBLIC_KEYS) {
    return keys;
  }

  const parsed = JSON.parse(env.JWT_PUBLIC_KEYS) as Record<string, string>;

  for (const [keyId, publicKey] of Object.entries(parsed)) {
    keys.set(keyId, publicKey);
  }

  return keys;
}

async function resolveRs256PublicKey(token: DecodedJwtWithHeader) {
  const alg = token.header?.alg;
  const kid = token.header?.kid;

  if (alg !== "RS256") {
    throw new Error("Unsupported JWT algorithm");
  }

  if (typeof kid !== "string") {
    throw new Error("JWT kid is required for RS256 verification");
  }

  const publicKey = jwtPublicKeyring().get(kid);

  if (!publicKey) {
    throw new Error("Unknown JWT kid");
  }

  return publicKey;
}

function buildJwtOptions(): FastifyJWTOptions {
  if (env.JWT_ALGORITHM === "RS256") {
    if (!env.JWT_PRIVATE_KEY || !env.JWT_KEY_ID) {
      throw new Error(
        "JWT_PRIVATE_KEY and JWT_KEY_ID are required when JWT_ALGORITHM=RS256"
      );
    }

    return {
      decode: {
        complete: true,
      },
      secret: {
        private: env.JWT_PRIVATE_KEY,
        public: resolveRs256PublicKey,
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
