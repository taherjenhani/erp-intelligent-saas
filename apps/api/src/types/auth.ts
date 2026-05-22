import { Role } from "@prisma/client";

export type AccessTokenPayload = {
  sub: string;
  email: string;
  role: Role;
  sessionId: string;
  storeIds: string[];
};

export type RefreshTokenPayload = {
  sub: string;
  sessionId: string;
  tokenId: string;
  familyId: string;
};