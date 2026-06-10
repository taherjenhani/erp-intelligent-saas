export type AppErrorCode =
  | "AUTH_ACCOUNT_DISABLED"
  | "AUTH_EMAIL_ALREADY_EXISTS"
  | "AUTH_EMAIL_NOT_VERIFIED"
  | "AUTH_INVALID_CREDENTIALS"
  | "AUTH_INVALID_REFRESH_TOKEN"
  | "AUTH_INVALID_RESET_TOKEN"
  | "AUTH_INVALID_VERIFICATION_TOKEN"
  | "AUTH_PASSWORD_REUSED"
  | "AUTH_REFRESH_TOKEN_MISSING"
  | "AUTH_REFRESH_ALREADY_ROTATED"
  | "AUTH_REFRESH_TOKEN_REUSED"
  | "AUTH_SESSION_EXPIRED"
  | "AUTH_SESSION_NOT_FOUND"
  | "AUTH_SESSION_REVOKED"
  | "AUTH_TOO_MANY_ATTEMPTS"
  | "AUTH_UNAUTHORIZED"
  | "PERMISSION_DENIED"
  | "RATE_LIMIT_EXCEEDED"
  | "VALIDATION_FAILED";

export class AppError extends Error {
  constructor(
    public readonly code: AppErrorCode,
    message: string,
    public readonly statusCode: number
  ) {
    super(message);
    this.name = new.target.name;
  }
}

export class AuthError extends AppError {
  constructor(code: AppErrorCode, message: string, statusCode = 401) {
    super(code, message, statusCode);
  }
}

export class ValidationError extends AppError {
  constructor(message = "Validation failed") {
    super("VALIDATION_FAILED", message, 400);
  }
}

export class PermissionError extends AppError {
  constructor(message = "Permission denied") {
    super("PERMISSION_DENIED", message, 403);
  }
}
