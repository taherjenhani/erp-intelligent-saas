import "dotenv/config";
import { z } from "zod";

const DEVELOPMENT_CSRF_SECRET =
  "development-csrf-secret-change-before-prod";
const DEVELOPMENT_TOKEN_HASH_SECRET =
  "development-token-hash-secret-change-before-prod";
const DEVELOPMENT_EMAIL_OUTBOX_ENCRYPTION_KEY =
  "development-email-outbox-encryption-key-change-before-prod";
const DEVELOPMENT_EMAIL_OUTBOX_ENCRYPTION_KEY_ID = "local-dev";
const DEVELOPMENT_REFRESH_IDEMPOTENCY_SECRET =
  "development-refresh-idempotency-secret-change-before-prod";
const DEVELOPMENT_CORS_ORIGIN = "http://localhost:3000";
const DEVELOPMENT_PASSWORD_PEPPER_KEY_ID = "local-dev";
const LEGACY_SECRET_FALLBACK_DEADLINE =
  "2026-09-30T00:00:00.000Z";
const KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;

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

function hasAnyLocalCorsOrigin(value: string) {
  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
    .some((origin) => isLocalUrl(origin));
}

function isValidDateTime(value: string) {
  return !Number.isNaN(Date.parse(value));
}

function parseEmailOutboxKeyring(value: string | undefined) {
  if (!value) {
    return {};
  }

  try {
    const parsed = JSON.parse(value) as unknown;

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return null;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function parseSecretKeyring(value: string | undefined) {
  if (!value) {
    return {};
  }

  try {
    const parsed = JSON.parse(value) as unknown;

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return null;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

const envSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),

    PORT: z.coerce.number().default(5000),

    DATABASE_URL: z.string().min(1),
    SHADOW_DATABASE_URL: z.string().url().optional(),

    CORS_ORIGIN: z.string().default(DEVELOPMENT_CORS_ORIGIN),

    APP_URL: z.string().url().default("http://localhost:3000"),
    EXPOSE_AUTH_TOKENS: booleanFromEnv.default(false),

    COOKIE_DOMAIN: z.string().optional(),

    CSRF_SECRET: z
      .string()
      .min(32, "CSRF_SECRET must contain at least 32 characters")
      .default(DEVELOPMENT_CSRF_SECRET),

    LOGIN_RATE_LIMIT_MAX: z.coerce.number().default(5),
    LOGIN_RATE_LIMIT_WINDOW: z.string().default("1 minute"),
    LOGIN_ATTEMPT_WINDOW_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(15 * 60 * 1000),
    LOGIN_ATTEMPT_EMAIL_MAX: z.coerce
      .number()
      .int()
      .positive()
      .default(5),
    LOGIN_ATTEMPT_IP_MAX: z.coerce
      .number()
      .int()
      .positive()
      .default(20),
    PASSWORD_HISTORY_LIMIT: z.coerce
      .number()
      .int()
      .min(0)
      .default(5),
    AUTH_RATE_LIMIT_MAX: z.coerce.number().default(10),
    AUTH_RATE_LIMIT_WINDOW: z.string().default("10 minutes"),
    RATE_LIMIT_REDIS_URL: z.string().url().optional(),
    TRUST_PROXY: booleanFromEnv.default(false),
    REFRESH_TOKEN_REUSE_GRACE_MS: z.coerce
      .number()
      .positive()
      .default(5 * 1000),
    REFRESH_IDEMPOTENCY_TTL_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 1000),

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
    EMAIL_OUTBOX_ENCRYPTION_KEY: z
      .string()
      .min(
        32,
        "EMAIL_OUTBOX_ENCRYPTION_KEY must contain at least 32 characters"
      )
      .default(DEVELOPMENT_EMAIL_OUTBOX_ENCRYPTION_KEY),
    EMAIL_OUTBOX_ENCRYPTION_KEY_ID: z
      .string()
      .regex(KEY_ID_PATTERN, "EMAIL_OUTBOX_ENCRYPTION_KEY_ID is invalid")
      .default(DEVELOPMENT_EMAIL_OUTBOX_ENCRYPTION_KEY_ID),
    EMAIL_OUTBOX_ENCRYPTION_KEYS: z.string().optional(),
    EMAIL_OUTBOX_WORKER_ENABLED: booleanFromEnv.default(false),
    EMAIL_OUTBOX_WORKER_INTERVAL_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 1000),
    EMAIL_OUTBOX_LOCK_HEARTBEAT_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 1000),
    METRICS_ENABLED: booleanFromEnv.default(false),
    METRICS_TOKEN: z.string().min(16).optional(),
    METRICS_INSTANCE_ID: z.string().min(1).optional(),
    TOKEN_CLEANUP_WORKER_ENABLED: booleanFromEnv.default(false),
    TOKEN_CLEANUP_WORKER_INTERVAL_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(60 * 60 * 1000),
    HELMET_CSP_ENABLED: booleanFromEnv.default(false),

    JWT_ACCESS_SECRET: z
      .string()
      .min(32, "JWT_ACCESS_SECRET must contain at least 32 characters"),
    JWT_ISSUER: z.string().min(1).default("erp-api"),
    JWT_AUDIENCE: z.string().min(1).default("erp-app"),

    PASSWORD_PEPPER: z
      .string()
      .min(32, "PASSWORD_PEPPER must contain at least 32 characters"),
    PASSWORD_PEPPER_KEY_ID: z
      .string()
      .regex(KEY_ID_PATTERN, "PASSWORD_PEPPER_KEY_ID is invalid")
      .default(DEVELOPMENT_PASSWORD_PEPPER_KEY_ID),
    PASSWORD_PEPPER_KEYS: z.string().optional(),
    TOKEN_HASH_SECRET: z
      .string()
      .min(32, "TOKEN_HASH_SECRET must contain at least 32 characters")
      .default(DEVELOPMENT_TOKEN_HASH_SECRET),
    REFRESH_IDEMPOTENCY_SECRET: z
      .string()
      .min(
        32,
        "REFRESH_IDEMPOTENCY_SECRET must contain at least 32 characters"
      )
      .default(DEVELOPMENT_REFRESH_IDEMPOTENCY_SECRET),
    LEGACY_SECRET_FALLBACK_UNTIL: z
      .string()
      .refine(
        isValidDateTime,
        "LEGACY_SECRET_FALLBACK_UNTIL must be a valid date"
      )
      .default(LEGACY_SECRET_FALLBACK_DEADLINE),
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

    if (
      env.REFRESH_IDEMPOTENCY_SECRET === env.PASSWORD_PEPPER ||
      env.REFRESH_IDEMPOTENCY_SECRET === env.TOKEN_HASH_SECRET
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["REFRESH_IDEMPOTENCY_SECRET"],
        message:
          "REFRESH_IDEMPOTENCY_SECRET must be different from PASSWORD_PEPPER and TOKEN_HASH_SECRET",
      });
    }

    const passwordPepperKeyring = parseSecretKeyring(
      env.PASSWORD_PEPPER_KEYS
    );

    if (passwordPepperKeyring === null) {
      ctx.addIssue({
        code: "custom",
        path: ["PASSWORD_PEPPER_KEYS"],
        message:
          "PASSWORD_PEPPER_KEYS must be a JSON object of key ids to secrets",
      });
    } else {
      for (const [keyId, secret] of Object.entries(passwordPepperKeyring)) {
        if (!KEY_ID_PATTERN.test(keyId)) {
          ctx.addIssue({
            code: "custom",
            path: ["PASSWORD_PEPPER_KEYS"],
            message: `Invalid password pepper key id: ${keyId}`,
          });
        }

        if (typeof secret !== "string" || secret.length < 32) {
          ctx.addIssue({
            code: "custom",
            path: ["PASSWORD_PEPPER_KEYS"],
            message:
              "Every PASSWORD_PEPPER_KEYS secret must contain at least 32 characters",
          });
        }
      }

      if (
        env.PASSWORD_PEPPER_KEYS &&
        !(env.PASSWORD_PEPPER_KEY_ID in passwordPepperKeyring)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["PASSWORD_PEPPER_KEY_ID"],
          message:
            "PASSWORD_PEPPER_KEY_ID must exist in PASSWORD_PEPPER_KEYS",
        });
      }
    }

    if (
      env.EMAIL_OUTBOX_LOCK_HEARTBEAT_MS >=
      env.EMAIL_OUTBOX_LOCK_TIMEOUT_MS
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["EMAIL_OUTBOX_LOCK_HEARTBEAT_MS"],
        message:
          "EMAIL_OUTBOX_LOCK_HEARTBEAT_MS must be lower than EMAIL_OUTBOX_LOCK_TIMEOUT_MS",
      });
    }

    const emailKeyring = parseEmailOutboxKeyring(
      env.EMAIL_OUTBOX_ENCRYPTION_KEYS
    );

    if (emailKeyring === null) {
      ctx.addIssue({
        code: "custom",
        path: ["EMAIL_OUTBOX_ENCRYPTION_KEYS"],
        message:
          "EMAIL_OUTBOX_ENCRYPTION_KEYS must be a JSON object of key ids to secrets",
      });
    } else {
      for (const [keyId, secret] of Object.entries(emailKeyring)) {
        if (!KEY_ID_PATTERN.test(keyId)) {
          ctx.addIssue({
            code: "custom",
            path: ["EMAIL_OUTBOX_ENCRYPTION_KEYS"],
            message: `Invalid email outbox encryption key id: ${keyId}`,
          });
        }

        if (typeof secret !== "string" || secret.length < 32) {
          ctx.addIssue({
            code: "custom",
            path: ["EMAIL_OUTBOX_ENCRYPTION_KEYS"],
            message:
              "Every EMAIL_OUTBOX_ENCRYPTION_KEYS secret must contain at least 32 characters",
          });
        }
      }

      if (
        env.EMAIL_OUTBOX_ENCRYPTION_KEYS &&
        !(env.EMAIL_OUTBOX_ENCRYPTION_KEY_ID in emailKeyring)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["EMAIL_OUTBOX_ENCRYPTION_KEY_ID"],
          message:
            "EMAIL_OUTBOX_ENCRYPTION_KEY_ID must exist in EMAIL_OUTBOX_ENCRYPTION_KEYS",
        });
      }
    }

    if (env.METRICS_ENABLED && !env.METRICS_TOKEN) {
      ctx.addIssue({
        code: "custom",
        path: ["METRICS_TOKEN"],
        message: "METRICS_TOKEN is required when metrics are enabled",
      });
    }

    if (env.NODE_ENV !== "production") {
      return;
    }

    if (env.CORS_ORIGIN === DEVELOPMENT_CORS_ORIGIN) {
      ctx.addIssue({
        code: "custom",
        path: ["CORS_ORIGIN"],
        message: "CORS_ORIGIN must be explicit in production",
      });
    }

    if (hasAnyLocalCorsOrigin(env.CORS_ORIGIN)) {
      ctx.addIssue({
        code: "custom",
        path: ["CORS_ORIGIN"],
        message:
          "CORS_ORIGIN must not contain local addresses in production",
      });
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

    if (
      env.REFRESH_IDEMPOTENCY_SECRET ===
      DEVELOPMENT_REFRESH_IDEMPOTENCY_SECRET
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["REFRESH_IDEMPOTENCY_SECRET"],
        message:
          "REFRESH_IDEMPOTENCY_SECRET must be explicit in production",
      });
    }

    if (
      env.EMAIL_OUTBOX_ENCRYPTION_KEY ===
      DEVELOPMENT_EMAIL_OUTBOX_ENCRYPTION_KEY
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["EMAIL_OUTBOX_ENCRYPTION_KEY"],
        message:
          "EMAIL_OUTBOX_ENCRYPTION_KEY must be explicit in production",
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
