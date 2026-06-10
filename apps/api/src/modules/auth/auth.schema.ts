import { z } from "zod";

const passwordSchema = z
  .string()
  .min(8, "Password must contain at least 8 characters")
  .max(72, "Password must not exceed 72 characters")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

const authTokenSchema = z
  .string()
  .length(128)
  .regex(/^[a-f0-9]+$/);

export const registerSchema = z.object({
  firstName: z.string().trim().min(2).max(50),
  lastName: z.string().trim().min(2).max(50),
  email: z.string().trim().email().toLowerCase(),
  password: passwordSchema,
  storeId: z
    .string()
    .cuid("Store id must be a valid cuid")
    .optional(),
}).strict();

export const loginSchema = z.object({
  email: z.string().trim().email().toLowerCase(),
  password: z.string().min(1).max(72),
}).strict();

export const verifyEmailSchema = z.object({
  token: authTokenSchema,
}).strict();

export const resendEmailVerificationSchema = z.object({
  email: z.string().trim().email().toLowerCase(),
}).strict();

export const requestPasswordResetSchema = z.object({
  email: z.string().trim().email().toLowerCase(),
}).strict();

export const resetPasswordSchema = z.object({
  token: authTokenSchema,
  password: passwordSchema,
}).strict();

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(72),
    newPassword: passwordSchema,
  })
  .strict()
  .refine(
    (data) => data.currentPassword !== data.newPassword,
    {
      message: "New password must be different",
      path: ["newPassword"],
    }
  );

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;
export type ResendEmailVerificationInput = z.infer<
  typeof resendEmailVerificationSchema
>;
export type RequestPasswordResetInput = z.infer<
  typeof requestPasswordResetSchema
>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
