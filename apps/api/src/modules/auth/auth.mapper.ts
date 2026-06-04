import type { PublicUserRecord } from "./auth.types";

export function toPublicUser(user: PublicUserRecord) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    role: user.role,
    platformRole: user.platformRole,
    emailVerified: Boolean(user.emailVerifiedAt),
    storeIds: user.storeAccesses.map((access) => access.storeId),
    storeRoles: Object.fromEntries(
      user.storeAccesses.map((access) => [
        access.storeId,
        access.role,
      ])
    ),
    organizationIds: user.memberships.map(
      (membership) => membership.organizationId
    ),
    organizationRoles: Object.fromEntries(
      user.memberships.map((membership) => [
        membership.organizationId,
        membership.role,
      ])
    ),
  };
}
