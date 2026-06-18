import crypto from "crypto";
import { env } from "../config/env";
import { isLegacySecretFallbackEnabled } from "./legacySecrets";

const REFRESH_TOKEN_BYTES = 64;

function parseTokenHashKeyring() {
  const secrets = [env.TOKEN_HASH_SECRET];

  if (!env.TOKEN_HASH_SECRET_KEYS) {
    return secrets;
  }

  const parsed = JSON.parse(env.TOKEN_HASH_SECRET_KEYS) as Record<
    string,
    string
  >;

  return [
    ...secrets,
    ...Object.entries(parsed)
      .filter(([, secret]) => secret !== env.TOKEN_HASH_SECRET)
      .map(([, secret]) => secret),
  ];
}

export function generateRandomToken(): string {
  return crypto
    .randomBytes(REFRESH_TOKEN_BYTES)
    .toString("hex");
}

export function generateFamilyId(): string {
  return crypto.randomUUID();
}

export async function hashToken(
  token: string
): Promise<string> {
  return hashTokenWithSecret(token, env.TOKEN_HASH_SECRET);
}

async function hashTokenWithSecret(
  token: string,
  secret: string
): Promise<string> {
  return crypto
    .createHmac("sha256", secret)
    .update(token)
    .digest("hex");
}

export async function getTokenHashCandidates(
  token: string
): Promise<string[]> {
  const candidates = await Promise.all(
    parseTokenHashKeyring().map((secret) =>
      hashTokenWithSecret(token, secret)
    )
  );

  if (isLegacySecretFallbackEnabled()) {
    candidates.push(await hashTokenWithSecret(token, env.PASSWORD_PEPPER));
  }

  return [...new Set(candidates)];
}

export async function verifyToken(
  token: string,
  tokenHash: string
): Promise<boolean> {
  const expected = Buffer.from(tokenHash, "hex");
  const candidates = await getTokenHashCandidates(token);

  return candidates.some((candidate) => {
    const actual = Buffer.from(candidate, "hex");

    return (
      expected.length === actual.length &&
      crypto.timingSafeEqual(expected, actual)
    );
  });
}
