import { describe, it, expect, mock, beforeEach } from "bun:test";
import { prisma } from "../__mocks__/prisma";

mock.module("@/libs/prisma", () => {
  prisma.$transaction = mock(async (callback) => {
    return await callback(prisma);
  });

  return { prisma };
});

import { RbacService } from "@/modules/rbac/service";

describe("RBAC Service", () => {
  beforeEach(() => {
    prisma.feature.create.mockReset();
    prisma.role.findMany.mockReset();
    prisma.roleFeature.createMany.mockReset();
    prisma.role.create.mockReset();
    prisma.role.update.mockReset();
    prisma.roleFeature.deleteMany.mockReset();
    prisma.role.findUniqueOrThrow.mockReset();
    prisma.feature.findMany.mockReset();
  });

  describe("Features", () => {
    it("should get all features", async () => {
      const mockFeatures = [{ id: "1", name: "User" }];
      prisma.feature.findMany.mockResolvedValue(mockFeatures);

      const result = await RbacService.getAllFeatures();

      expect(result).toEqual(mockFeatures as any);
      expect(prisma.feature.findMany).toHaveBeenCalled();
    });

    it("should create feature WITHOUT defaults", async () => {
      const input = { name: "New Feat" };
      const created = { id: "1", ...input };

      (prisma.feature.create as any).mockResolvedValue(created);
      const result = await RbacService.createFeature(input);
      expect(result).toEqual(created as any);
      expect(prisma.roleFeature.createMany).not.toHaveBeenCalled();
    });

    it("should create feature WITH defaults (Auto-Assign)", async () => {
      const input = {
        name: "New Feat",
        defaultPermissions: { canRead: true, canCreate: false },
      };

      const newFeature = { id: "feat_1", name: "New Feat" };
      const existingRoles = [
        { id: "role_admin", name: "Super Admin" },
        { id: "role_staff", name: "Staff" },
      ];

      // Mock the transaction flow
      (prisma.feature.create as any).mockResolvedValue(newFeature);
      (prisma.role.findMany as any).mockResolvedValue(existingRoles);
      (prisma.roleFeature.createMany as any).mockResolvedValue({ count: 2 });

      await RbacService.createFeature(input as any);

      // Verify transaction logic
      expect(prisma.roleFeature.createMany).toHaveBeenCalledWith({
        data: [
          // Admin should get FULL ACCESS (Override Logic)
          {
            roleId: "role_admin",
            featureId: "feat_1",
            canCreate: true,
            canRead: true,
            canUpdate: true,
            canDelete: true,
            canPrint: true,
          },
          // Staff should get DEFAULTS
          {
            roleId: "role_staff",
            featureId: "feat_1",
            canRead: true,
            canCreate: false,
          },
        ],
      });
    });
  });

  describe("Roles", () => {
    it("should create role with permissions", async () => {
      const input = {
        name: "Manager",
        permissions: [{ featureId: "f1", canRead: true, canCreate: false }],
      };

      const expectedRole = { id: "r1", name: "Manager" };
      (prisma.role.create as any).mockResolvedValue(expectedRole);

      const result = await RbacService.createRole(input as any);

      expect(result).toEqual(expectedRole as any);
      expect(prisma.role.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: "Manager",
            permissions: {
              create: expect.arrayContaining([
                expect.objectContaining({ featureId: "f1", canRead: true }),
              ]),
            },
          }),
        }),
      );
    });

    it("should update role and sync permissions (Wipe & Replace)", async () => {
      const roleId = "r1";
      const input = {
        name: "Updated Manager",
        permissions: [{ featureId: "f1", canRead: true, canCreate: true }],
      };

      // Mock responses
      (prisma.role.update as any).mockResolvedValue({});
      (prisma.roleFeature.deleteMany as any).mockResolvedValue({});
      (prisma.roleFeature.createMany as any).mockResolvedValue({});
      (prisma.role.findUniqueOrThrow as any).mockResolvedValue({
        id: roleId,
        name: input.name,
      });

      const result = await RbacService.updateRole(roleId, input as any);

      // 1. Check Update
      expect(prisma.role.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: roleId },
          data: expect.objectContaining({ name: "Updated Manager" }),
        }),
      );

      // 2. Check Wipe
      expect(prisma.roleFeature.deleteMany).toHaveBeenCalledWith({
        where: { roleId },
      });

      // 3. Check Replace
      expect(prisma.roleFeature.createMany).toHaveBeenCalledWith({
        data: expect.arrayContaining([
          expect.objectContaining({ roleId, featureId: "f1", canCreate: true }),
        ]),
      });

      // 4. Check Return
      expect(result.name).toBe("Updated Manager");
    });

    it("should skip permission sync if permissions input is missing", async () => {
      const roleId = "r1";
      const input = { name: "Just Name Change" }; // No permissions array

      (prisma.role.update as any).mockResolvedValue({});
      (prisma.role.findUniqueOrThrow as any).mockResolvedValue(input);

      await RbacService.updateRole(roleId, input as any);

      expect(prisma.role.update).toHaveBeenCalled();
      // Should NOT wipe or create permissions
      expect(prisma.roleFeature.deleteMany).not.toHaveBeenCalled();
      expect(prisma.roleFeature.createMany).not.toHaveBeenCalled();
    });
  });
});
