import { PrismaClient, Role } from "@prisma/client";

const prisma = new PrismaClient();

const permissions = [
  "stores.read",
  "stores.write",
  "warehouses.read",
  "warehouses.write",
  "users.read",
  "users.write",
  "reports.read",
] as const;

const rolePermissions: Record<Role, readonly string[]> = {
  SUPER_ADMIN: permissions,
  ADMIN: permissions,
  MANAGER: [
    "stores.read",
    "warehouses.read",
    "warehouses.write",
    "reports.read",
  ],
  EMPLOYEE: ["stores.read", "warehouses.read"],
};

async function main() {
  for (const key of permissions) {
    await prisma.permission.upsert({
      where: { key },
      update: {},
      create: {
        key,
        description: key,
      },
    });
  }

  for (const [role, keys] of Object.entries(rolePermissions) as [
    Role,
    readonly string[],
  ][]) {
    for (const key of keys) {
      const permission = await prisma.permission.findUniqueOrThrow({
        where: { key },
        select: { id: true },
      });

      await prisma.rolePermission.upsert({
        where: {
          role_permissionId: {
            role,
            permissionId: permission.id,
          },
        },
        update: {},
        create: {
          role,
          permissionId: permission.id,
        },
      });
    }
  }
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (error) => {
    console.error(error);
    await prisma.$disconnect();
    process.exit(1);
  });
