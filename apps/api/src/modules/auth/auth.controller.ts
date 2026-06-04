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
  logoutUser,
  refreshSession,
  registerUser,
  resendEmailVerification,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
} from "./auth.service";

function getRequestContext(request: FastifyRequest) {
  return {
    ipAddress: request.ip,
    userAgent: request.headers["user-agent"],
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

  return reply.status(201).send({
    success: true,
    message: "User created successfully",
    data: {
      user: result.user,
      emailVerificationToken:
        env.EXPOSE_AUTH_TOKENS
          ? result.emailVerificationToken
          : undefined,
    },
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
    getRequestContext(request)
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
