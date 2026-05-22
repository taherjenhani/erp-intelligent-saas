import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().default(5000),

  DATABASE_URL: z.string().min(1),

  JWT_SECRET: z
    .string()
    .min(32, "JWT_SECRET must contain at least 32 characters"),

  PASSWORD_PEPPER: z
    .string()
    .min(32, "PASSWORD_PEPPER must contain at least 32 characters"),
});

export const env = envSchema.parse(process.env);