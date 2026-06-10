import crypto from "crypto";
import { env } from "../config/env";
import { isLegacySecretFallbackEnabled } from "./legacySecrets";

const REFRESH_TOKEN_BYTES = 64;

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
  const candidates = [
    await hashTokenWithSecret(token, env.TOKEN_HASH_SECRET),
  ];

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
