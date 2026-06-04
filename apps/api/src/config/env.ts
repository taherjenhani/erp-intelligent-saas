import "dotenv/config";
import { z } from "zod";

const DEVELOPMENT_CSRF_SECRET =
  "development-csrf-secret-change-before-prod";
const DEVELOPMENT_TOKEN_HASH_SECRET =
  "development-token-hash-secret-change-before-prod";

const booleanFromEnv = z.preprocess((value) => {
  if (typeof value !== "string") {
    return value;
  }

  const normalizedValue = value.trim().toLowerCase();

  if (["true", "1", "yes", "on"].includes(normalizedValue)) {
    return true;
  }

  if (["false", "0", "no", "off"].includes(normalizedValue)) {
    return false;
  }

  return value;
}, z.boolean());

function isLocalUrl(value: string) {
  try {
    const url = new URL(value);

    return ["localhost", "127.0.0.1", "::1", "[::1]"].includes(
      url.hostname
    );
  } catch {
    return false;
  }
}

function hasOnlyLocalCorsOrigins(value: string) {
  const origins = value
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

  return (
    origins.length > 0 &&
    origins.every((origin) => isLocalUrl(origin))
  );
}

const envSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),

    PORT: z.coerce.number().default(5000),

    DATABASE_URL: z.string().min(1),
    SHADOW_DATABASE_URL: z.string().url().optional(),

    CORS_ORIGIN: z.string().default("http://localhost:3000"),

    APP_URL: z.string().url().default("http://localhost:3000"),
    EXPOSE_AUTH_TOKENS: booleanFromEnv.default(false),

    COOKIE_DOMAIN: z.string().optional(),

    CSRF_SECRET: z
      .string()
      .min(32, "CSRF_SECRET must contain at least 32 characters")
      .default(DEVELOPMENT_CSRF_SECRET),

    LOGIN_RATE_LIMIT_MAX: z.coerce.number().default(5),
    LOGIN_RATE_LIMIT_WINDOW: z.string().default("1 minute"),
    AUTH_RATE_LIMIT_MAX: z.coerce.number().default(10),
    AUTH_RATE_LIMIT_WINDOW: z.string().default("10 minutes"),
    RATE_LIMIT_REDIS_URL: z.string().url().optional(),
    TRUST_PROXY: booleanFromEnv.default(false),
    REFRESH_TOKEN_REUSE_GRACE_MS: z.coerce
      .number()
      .positive()
      .default(10 * 1000),

    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().default(587),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    SMTP_FROM: z.string().email().default("noreply@example.com"),
    EMAIL_OUTBOX_BATCH_SIZE: z.coerce.number().default(20),
    EMAIL_OUTBOX_LOCK_TIMEOUT_MS: z.coerce
      .number()
      .positive()
      .default(10 * 60 * 1000),

    JWT_ACCESS_SECRET: z
      .string()
      .min(32, "JWT_ACCESS_SECRET must contain at least 32 characters"),

    PASSWORD_PEPPER: z
      .string()
      .min(32, "PASSWORD_PEPPER must contain at least 32 characters"),
    TOKEN_HASH_SECRET: z
      .string()
      .min(32, "TOKEN_HASH_SECRET must contain at least 32 characters")
      .default(DEVELOPMENT_TOKEN_HASH_SECRET),
  })
  .superRefine((env, ctx) => {
    const canExposeAuthTokens =
      env.NODE_ENV === "test" ||
      (env.NODE_ENV === "development" &&
        isLocalUrl(env.APP_URL) &&
        hasOnlyLocalCorsOrigins(env.CORS_ORIGIN));

    if (env.EXPOSE_AUTH_TOKENS && !canExposeAuthTokens) {
      ctx.addIssue({
        code: "custom",
        path: ["EXPOSE_AUTH_TOKENS"],
        message:
          "EXPOSE_AUTH_TOKENS is only allowed in test or local development",
      });
    }

    if (env.PASSWORD_PEPPER === env.TOKEN_HASH_SECRET) {
      ctx.addIssue({
        code: "custom",
        path: ["TOKEN_HASH_SECRET"],
        message:
          "TOKEN_HASH_SECRET must be different from PASSWORD_PEPPER",
      });
    }

    if (env.NODE_ENV !== "production") {
      return;
    }

    if (env.CSRF_SECRET === DEVELOPMENT_CSRF_SECRET) {
      ctx.addIssue({
        code: "custom",
        path: ["CSRF_SECRET"],
        message: "CSRF_SECRET must be explicit in production",
      });
    }

    if (env.TOKEN_HASH_SECRET === DEVELOPMENT_TOKEN_HASH_SECRET) {
      ctx.addIssue({
        code: "custom",
        path: ["TOKEN_HASH_SECRET"],
        message: "TOKEN_HASH_SECRET must be explicit in production",
      });
    }

    if (!env.SMTP_HOST) {
      ctx.addIssue({
        code: "custom",
        path: ["SMTP_HOST"],
        message: "SMTP_HOST is required in production",
      });
    }

    if (isLocalUrl(env.APP_URL)) {
      ctx.addIssue({
        code: "custom",
        path: ["APP_URL"],
        message:
          "APP_URL must not point to a local address in production",
      });
    }

    if (!env.RATE_LIMIT_REDIS_URL) {
      ctx.addIssue({
        code: "custom",
        path: ["RATE_LIMIT_REDIS_URL"],
        message: "RATE_LIMIT_REDIS_URL is required in production",
      });
    }
  });

export function parseEnv(input: Record<string, unknown>) {
  return envSchema.parse(input);
}

export const env = parseEnv(process.env);
