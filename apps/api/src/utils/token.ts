import crypto from "crypto";
import { env } from "../config/env";

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
  return crypto
    .createHmac("sha256", env.PASSWORD_PEPPER)
    .update(token)
    .digest("hex");
}

export async function verifyToken(
  token: string,
  tokenHash: string
): Promise<boolean> {
  const nextTokenHash = await hashToken(token);
  const expected = Buffer.from(tokenHash, "hex");
  const actual = Buffer.from(nextTokenHash, "hex");

  return (
    expected.length === actual.length &&
    crypto.timingSafeEqual(expected, actual)
  );
}
