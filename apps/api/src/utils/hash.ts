import bcrypt from "bcrypt";
import crypto from "crypto";
import { env } from "../config/env";
import { isLegacySecretFallbackEnabled } from "./legacySecrets";

const SALT_ROUNDS = 12;

function parsePasswordPepperKeyring() {
  const keys = new Map<string, string>();
  keys.set(env.PASSWORD_PEPPER_KEY_ID, env.PASSWORD_PEPPER);

  if (!env.PASSWORD_PEPPER_KEYS) {
    return keys;
  }

  const parsed = JSON.parse(env.PASSWORD_PEPPER_KEYS) as Record<
    string,
    string
  >;

  for (const [keyId, secret] of Object.entries(parsed)) {
    keys.set(keyId, secret);
  }

  return keys;
}

export function activePasswordPepperKeyId() {
  return env.PASSWORD_PEPPER_KEY_ID;
}

function passwordDigest(password: string, secret: string): string {
  return crypto
    .createHmac("sha256", secret)
    .update(password)
    .digest("hex");
}

function legacyPepperedPassword(password: string): string {
  return password + env.PASSWORD_PEPPER;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(
    passwordDigest(password, env.PASSWORD_PEPPER),
    SALT_ROUNDS
  );
}

export async function verifyPassword(
  password: string,
  hashedPassword: string,
  passwordPepperKeyId?: string | null
): Promise<boolean> {
  const keyring = parsePasswordPepperKeyring();
  const orderedSecrets = [
    ...(passwordPepperKeyId && keyring.has(passwordPepperKeyId)
      ? [keyring.get(passwordPepperKeyId)]
      : []),
    env.PASSWORD_PEPPER,
    ...Array.from(keyring.entries())
      .filter(([keyId]) => keyId !== passwordPepperKeyId)
      .map(([, secret]) => secret),
  ].filter((secret): secret is string => Boolean(secret));

  for (const secret of [...new Set(orderedSecrets)]) {
    if (
      await bcrypt.compare(
        passwordDigest(password, secret),
        hashedPassword
      )
    ) {
      return true;
    }
  }

  if (!isLegacySecretFallbackEnabled()) {
    return false;
  }

  return bcrypt.compare(
    legacyPepperedPassword(password),
    hashedPassword
  );
}
