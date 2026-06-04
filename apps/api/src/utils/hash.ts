import bcrypt from "bcrypt";
import crypto from "crypto";
import { env } from "../config/env";

const SALT_ROUNDS = 12;

function passwordDigest(password: string): string {
  return crypto
    .createHmac("sha256", env.PASSWORD_PEPPER)
    .update(password)
    .digest("hex");
}

function legacyPepperedPassword(password: string): string {
  return password + env.PASSWORD_PEPPER;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(passwordDigest(password), SALT_ROUNDS);
}

export async function verifyPassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  if (await bcrypt.compare(passwordDigest(password), hashedPassword)) {
    return true;
  }

  return bcrypt.compare(
    legacyPepperedPassword(password),
    hashedPassword
  );
}
