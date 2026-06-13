import crypto from "crypto";
import type { FastifyPluginAsync } from "fastify";
import fp from "fastify-plugin";

import { env } from "../config/env";

function jwtPublicKeys() {
  const keys = new Map<string, string>();

  if (env.JWT_KEY_ID && env.JWT_PUBLIC_KEY) {
    keys.set(env.JWT_KEY_ID, env.JWT_PUBLIC_KEY);
  }

  if (env.JWT_PUBLIC_KEYS) {
    const parsed = JSON.parse(env.JWT_PUBLIC_KEYS) as Record<string, string>;

    for (const [keyId, publicKey] of Object.entries(parsed)) {
      keys.set(keyId, publicKey);
    }
  }

  return keys;
}

function publicKeyToJwk(kid: string, publicKey: string) {
  const jwk = crypto
    .createPublicKey(publicKey)
    .export({ format: "jwk" });

  return {
    ...jwk,
    kid,
    use: "sig",
    alg: "RS256",
  };
}

const jwksPlugin: FastifyPluginAsync = async (app) => {
  app.get("/.well-known/jwks.json", async (_request, reply) => {
    if (env.JWT_ALGORITHM !== "RS256") {
      return reply.status(404).send({
        success: false,
        code: "JWKS_NOT_ENABLED",
        message: "JWKS is only available when JWT_ALGORITHM=RS256",
      });
    }

    return {
      keys: Array.from(jwtPublicKeys().entries()).map(
        ([kid, publicKey]) => publicKeyToJwk(kid, publicKey)
      ),
    };
  });
};

export default fp(jwksPlugin);
