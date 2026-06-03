import crypto from "crypto";
import bcrypt from "bcrypt";

const REFRESH_TOKEN_BYTES = 64;
const TOKEN_HASH_ROUNDS = 12;

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
  return bcrypt.hash(token, TOKEN_HASH_ROUNDS);
}

export async function verifyToken(
  token: string,
  tokenHash: string
): Promise<boolean> {
  return bcrypt.compare(token, tokenHash);
}