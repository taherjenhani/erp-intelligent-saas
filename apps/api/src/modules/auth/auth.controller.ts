import type { FastifyReply, FastifyRequest } from "fastify";

import { env } from "../../config/env";
import { AuthError } from "../../lib/errors";
import {
  clearRefreshCookie,
  setRefreshCookie,
  toAuthResponse,
} from "../../utils/authTokens";
import {
  changePasswordSchema,
  loginSchema,
  registerSchema,
  resendEmailVerificationSchema,
  requestPasswordResetSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from "./auth.schema";
import {
  changePassword,
  loginUser,
  logoutAllUserSessions,
  logoutUser,
  refreshSession,
  registerUser,
  resendEmailVerification,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
} from "./auth.service";

const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;

function getSingleHeaderValue(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function getRefreshIdempotencyKey(request: FastifyRequest) {
  const value =
    getSingleHeaderValue(request.headers["idempotency-key"]) ??
    getSingleHeaderValue(request.headers["x-idempotency-key"]);

  if (!value) {
    return null;
  }

  if (!IDEMPOTENCY_KEY_PATTERN.test(value)) {
    throw new AuthError(
      "VALIDATION_FAILED",
      "Invalid idempotency key",
      400
    );
  }

  return value;
}

function getRequestContext(request: FastifyRequest) {
  return {
    ipAddress: request.ip,
    userAgent: request.headers["user-agent"],
    correlationId: request.correlationId,
  };
}

function sendAuthResult(
  request: FastifyRequest,
  reply: FastifyReply,
  result: Awaited<ReturnType<typeof loginUser>>,
  message: string
) {
  const authResponse = toAuthResponse(
    request,
    result.user,
    result.session,
    result.refreshToken
  );

  setRefreshCookie(reply, authResponse.refreshToken);

  return reply.status(200).send({
    success: true,
    message,
    data: {
      accessToken: authResponse.accessToken,
      user: authResponse.user,
    },
  });
}

export async function registerController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const data = registerSchema.parse(request.body);
  const result = await registerUser(
    data,
    getRequestContext(request)
  );
  const canExposeDebugRegistrationData =
    env.EXPOSE_AUTH_TOKENS &&
    result.created &&
    result.user &&
    result.emailVerificationToken;

  return reply.status(202).send({
    success: true,
    message: "Registration request accepted",
    data: canExposeDebugRegistrationData
      ? {
          user: result.user,
          emailVerificationToken: result.emailVerificationToken,
        }
      : undefined,
  });
}

export async function loginController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = loginSchema.parse(request.body);
  const result = await loginUser(
    body,
    getRequestContext(request)
  );

  return sendAuthResult(
    request,
    reply,
    result,
    "Login successful"
  );
}

export async function refreshController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const refreshToken = request.cookies.refreshToken;

  if (!refreshToken) {
    throw new AuthError(
      "AUTH_REFRESH_TOKEN_MISSING",
      "Refresh token missing"
    );
  }

  const result = await refreshSession(
    refreshToken,
    {
      ...getRequestContext(request),
      idempotencyKey: getRefreshIdempotencyKey(request),
    }
  );

  return sendAuthResult(
    request,
    reply,
    result,
    "Token refreshed successfully"
  );
}

export async function logoutController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const refreshToken = request.cookies.refreshToken;

  if (refreshToken) {
    await logoutUser(refreshToken, getRequestContext(request));
  }

  clearRefreshCookie(reply);

  return reply.status(200).send({
    success: true,
    message: "Logout successful",
  });
}

export async function logoutAllController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.auth) {
    throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
  }

  await logoutAllUserSessions(
    request.auth.userId,
    getRequestContext(request)
  );

  clearRefreshCookie(reply);

  return reply.status(200).send({
    success: true,
    message: "All sessions logged out successfully",
  });
}

export async function meController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  return reply.status(200).send({
    success: true,
    data: request.auth,
  });
}

export async function csrfTokenController(
  _request: FastifyRequest,
  reply: FastifyReply
) {
  return reply.status(200).send({
    success: true,
    data: {
      csrfToken: reply.generateCsrf(),
    },
  });
}

export async function verifyEmailController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = verifyEmailSchema.parse(request.body);

  await verifyEmail(body, getRequestContext(request));

  return reply.status(200).send({
    success: true,
    message: "Email verified successfully",
  });
}

export async function resendEmailVerificationController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = resendEmailVerificationSchema.parse(request.body);
  const result = await resendEmailVerification(
    body,
    getRequestContext(request)
  );

  return reply.status(200).send({
    success: true,
    message:
      "If an active unverified account exists, a verification link has been prepared",
    data:
      env.EXPOSE_AUTH_TOKENS
        ? {
            emailVerificationToken:
              result.emailVerificationToken,
          }
        : undefined,
  });
}

export async function requestPasswordResetController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = requestPasswordResetSchema.parse(request.body);
  const result = await requestPasswordReset(
    body,
    getRequestContext(request)
  );

  return reply.status(200).send({
    success: true,
    message:
      "If an active account exists, a reset link has been prepared",
    data:
      env.EXPOSE_AUTH_TOKENS
        ? { resetToken: result.resetToken }
        : undefined,
  });
}

export async function resetPasswordController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = resetPasswordSchema.parse(request.body);

  await resetPassword(body, getRequestContext(request));

  return reply.status(200).send({
    success: true,
    message: "Password reset successfully",
  });
}

export async function changePasswordController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  if (!request.auth) {
    throw new AuthError("AUTH_UNAUTHORIZED", "Unauthorized");
  }

  const body = changePasswordSchema.parse(request.body);

  await changePassword(
    request.auth.userId,
    request.auth.sessionId,
    body,
    getRequestContext(request)
  );

  return reply.status(200).send({
    success: true,
    message: "Password changed successfully",
  });
}
