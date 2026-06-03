import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),

  PORT: z.coerce.number().default(5000),

  DATABASE_URL: z.string().min(1),

  CORS_ORIGIN: z.string().default("http://localhost:3000"),

  COOKIE_DOMAIN: z.string().optional(),

  CSRF_SECRET: z
    .string()
    .min(32, "CSRF_SECRET must contain at least 32 characters")
    .default("development-csrf-secret-change-before-prod"),

  LOGIN_RATE_LIMIT_MAX: z.coerce.number().default(5),
  LOGIN_RATE_LIMIT_WINDOW: z.string().default("1 minute"),

  JWT_ACCESS_SECRET: z
    .string()
    .min(32, "JWT_ACCESS_SECRET must contain at least 32 characters"),

  JWT_REFRESH_SECRET: z
    .string()
    .min(32, "JWT_REFRESH_SECRET must contain at least 32 characters"),

  PASSWORD_PEPPER: z
    .string()
    .min(32, "PASSWORD_PEPPER must contain at least 32 characters"),
});

export const env = envSchema.parse(process.env);
