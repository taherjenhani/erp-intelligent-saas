import type { PlatformRole, Role } from "@prisma/client";

export type AuthContextInput = {
  ipAddress?: string | null;
  userAgent?: string | null;
  correlationId?: string | null;
};

export type PublicUserRecord = {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  role: Role;
  platformRole: PlatformRole;
  emailVerifiedAt?: Date | null;
  storeAccesses: { storeId: string; role: Role }[];
  memberships: { organizationId: string; role: Role }[];
};
