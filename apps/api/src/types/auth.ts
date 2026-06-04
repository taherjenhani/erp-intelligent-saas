import { PlatformRole, Role } from "@prisma/client";

export type AccessTokenPayload = {
  sub: string;
  email: string;
  role: Role;
  platformRole: PlatformRole;
  sessionId: string;
  storeIds: string[];
  organizationIds: string[];
};

export type RefreshTokenPayload = {
  sub: string;
  sessionId: string;
  tokenId: string;
  familyId: string;
};
