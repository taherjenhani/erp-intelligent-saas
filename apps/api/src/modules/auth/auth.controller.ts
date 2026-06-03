import { FastifyReply, FastifyRequest } from "fastify";

import {
  loginSchema,
  registerSchema,
} from "./auth.schema";

import {
  loginUser,
  registerUser,refreshSession,logoutUser,
} from "./auth.service";


export async function registerController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const data = registerSchema.parse(request.body);

  const user = await registerUser(data);

  return reply.status(201).send({
    success: true,
    message: "User created successfully",
    data: user,
  });
}

export async function loginController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const body = loginSchema.parse(request.body);

  const result = await loginUser(
    body.email,
    body.password
  );

const accessToken = request.server.jwt.sign(
  {
    email: result.user.email,
    role: result.user.role,
    sessionId: result.session.id,
    storeIds: result.user.storeIds,
  },
  {
    sub: result.user.id,
    expiresIn: "15m",
  }
);
  reply.setCookie(
    "refreshToken",
    result.refreshToken,
    {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/api/auth",
      maxAge: 7 * 24 * 60 * 60,
    }
  );

  return reply.status(200).send({
    success: true,
    message: "Login successful",
    data: {
      accessToken,
      user: result.user,
    },
  });
}
export async function refreshController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const refreshToken =
    request.cookies.refreshToken;

  if (!refreshToken) {
    return reply.status(401).send({
      success: false,
      message: "Refresh token missing",
    });
  }

  const result = await refreshSession(refreshToken);

  const accessToken = request.server.jwt.sign(
    {
      email: result.user.email,
      role: result.user.role,
      sessionId: result.session.id,
      storeIds: result.user.storeIds,
    },
    {
      sub: result.user.id,
      expiresIn: "15m",
    }
  );

  reply.setCookie("refreshToken", result.refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    path: "/api/auth",
    maxAge: 7 * 24 * 60 * 60,
  });

  return reply.status(200).send({
    success: true,
    message: "Token refreshed successfully",
    data: {
      accessToken,
      user: result.user,
    },
  });
}
export async function logoutController(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const refreshToken = request.cookies.refreshToken;

  if (refreshToken) {
    await logoutUser(refreshToken);
  }

  reply.clearCookie("refreshToken", {
    path: "/api/auth",
  });

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
