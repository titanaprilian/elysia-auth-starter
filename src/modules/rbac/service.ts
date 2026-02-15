import { prisma } from "@/libs/prisma";
import type {
  CreateRoleInput,
  UpdateRoleInput,
  CreateFeatureInput,
  UpdateFeatureInput,
} from "./schema";
import { DeleteSystemError, InvalidFeatureIdError } from "./error";
import { Prisma } from "@generated/prisma";

// 🔒 Define system critical features and roles that cannot be touched
const PROTECTED_FEATURES = ["RBAC_management"];
const PROTECTED_ROLES = ["SuperAdmin"];

export const RbacService = {
  /**
   * =========================================
   * FEATURES (Resources)
   * Standard CRUD operations
   * =========================================
   */
  getAllFeatures: async (params: {
    page: number;
    limit: number;
    search?: string;
  }) => {
    const { page, limit, search } = params;
    const where: Prisma.FeatureWhereInput = {};

    if (search) {
      where.OR = [
        { name: { contains: search } },
        { description: { contains: search } },
      ];
    }

    // Calculate Skip
    const skip = (page - 1) * limit;

    const [features, total] = await prisma.$transaction([
      prisma.feature.findMany({
        where,
        skip,
        take: limit,
        orderBy: { name: "asc" },
      }),
      prisma.feature.count({ where }),
    ]);

    // Convert Date objects to ISO strings
    const featuresWithStringDates = features.map((feature) => ({
      ...feature,
      createdAt: feature.createdAt.toISOString(),
      updatedAt: feature.updatedAt.toISOString(),
    }));

    return {
      features: featuresWithStringDates,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  },

  createFeature: async (data: CreateFeatureInput) => {
    const { defaultPermissions, ...featureData } = data;

    return await prisma.$transaction(async (tx) => {
      const newFeature = await tx.feature.create({
        data: featureData,
      });

      if (defaultPermissions) {
        const allRoles = await tx.role.findMany({
          select: { id: true, name: true },
        });

        if (allRoles.length > 0) {
          const roleFeaturesData = allRoles.map((role) => {
            const isAdmin = role.name.toLowerCase().includes("admin");
            if (isAdmin) {
              return {
                roleId: role.id,
                featureId: newFeature.id,
                canCreate: true,
                canRead: true,
                canUpdate: true,
                canDelete: true,
                canPrint: true,
              };
            }

            return {
              roleId: role.id,
              featureId: newFeature.id,
              ...defaultPermissions,
            };
          });

          await tx.roleFeature.createMany({
            data: roleFeaturesData,
          });
        }
      }

      return {
        ...newFeature,
        createdAt: newFeature.createdAt.toISOString(),
        updatedAt: newFeature.updatedAt.toISOString(),
      };
    });
  },

  updateFeature: async (id: string, data: UpdateFeatureInput) => {
    const updatedFeature = await prisma.feature.update({
      where: { id },
      data,
    });

    return {
      ...updatedFeature,
      createdAt: updatedFeature.createdAt.toISOString(),
      updatedAt: updatedFeature.updatedAt.toISOString(),
    };
  },

  deleteFeature: async (id: string) => {
    const feature = await prisma.feature.findUniqueOrThrow({
      where: { id },
    });

    if (PROTECTED_FEATURES.includes(feature.name)) {
      throw new DeleteSystemError();
    }

    const deletedFreature = await prisma.feature.delete({
      where: { id },
    });

    return {
      ...deletedFreature,
      createdAt: deletedFreature.createdAt.toISOString(),
      updatedAt: deletedFreature.updatedAt.toISOString(),
    };
  },

  /**
   * =========================================
   * ROLES (with Permissions)
   * Complex CRUD handling relations
   * =========================================
   */
  getAllRoles: async (params: {
    page: number;
    limit: number;
    search?: string;
    feature?: string;
  }) => {
    const { page, limit, search, feature } = params;
    const where: Prisma.RoleWhereInput = {};

    if (search) {
      where.name = { contains: search };
    }

    if (feature) {
      where.permissions = {
        some: {
          feature: {
            name: { contains: feature },
          },
        },
      };
    }

    // Calculate Skip
    const skip = (page - 1) * limit;

    const [roles, total] = await prisma.$transaction([
      prisma.role.findMany({
        where,
        include: {
          permissions: {
            include: {
              feature: {
                select: { id: true, name: true },
              },
            },
          },
        },
        skip,
        take: limit,
        orderBy: { name: "asc" },
      }),
      prisma.role.count({ where }),
    ]);

    // Convert Date objects to ISO strings
    const roleWithStringDates = roles.map((role) => ({
      ...role,
      createdAt: role.createdAt.toISOString(),
      updatedAt: role.updatedAt.toISOString(),
    }));

    return {
      roles: roleWithStringDates,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  },

  getRoleOptions: async (params: {
    page: number;
    limit: number;
    search?: string;
  }) => {
    const { page, limit, search } = params;
    const where: Prisma.RoleWhereInput = {};

    if (search) {
      where.name = { contains: search };
    }

    const skip = (page - 1) * limit;

    const [roles, total] = await prisma.$transaction([
      prisma.role.findMany({
        where,
        select: { id: true, name: true },
        skip,
        take: limit,
        orderBy: { name: "asc" },
      }),
      prisma.role.count({ where }),
    ]);

    return {
      roles,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  },

  createRole: async (data: CreateRoleInput) => {
    return await prisma.$transaction(async (tx) => {
      // Validate featureIds if permissions are provided
      if (data.permissions && data.permissions.length > 0) {
        const featureIds = data.permissions.map((p) => p.featureId);
        const existingFeatures = await tx.feature.findMany({
          where: { id: { in: featureIds } },
          select: { id: true },
        });
        const existingFeatureIds = new Set(existingFeatures.map((f) => f.id));
        const invalidFeatureIds = featureIds.filter(
          (id) => !existingFeatureIds.has(id),
        );
        if (invalidFeatureIds.length > 0) {
          throw new InvalidFeatureIdError(
            "Invalid featureId(s): " + invalidFeatureIds.join(", "),
          );
        }
      }

      // Create the Role first
      const role = await tx.role.create({
        data: {
          name: data.name,
          description: data.description,
        },
      });

      // Fetch ALL system features
      // We need this list to guarantee we create a permission entry for every single feature
      const allFeatures = await tx.feature.findMany({ select: { id: true } });

      // Create a Lookup Map for incoming permissions (for faster matching)
      const providedPermsMap = new Map(
        (data.permissions || []).map((p) => [p.featureId, p]),
      );

      // We map over ALL features, not just the ones provided in the request
      const roleFeaturesData = allFeatures.map((feature) => {
        const provided = providedPermsMap.get(feature.id);

        return {
          roleId: role.id,
          featureId: feature.id,
          canCreate: provided?.canCreate ?? false,
          canRead: provided?.canRead ?? false,
          canUpdate: provided?.canUpdate ?? false,
          canDelete: provided?.canDelete ?? false,
          canPrint: provided?.canPrint ?? false,
        };
      });

      // Bulk Insert Permissions
      if (roleFeaturesData.length > 0) {
        await tx.roleFeature.createMany({
          data: roleFeaturesData,
        });
      }

      const newRole = await tx.role.findUniqueOrThrow({
        where: { id: role.id },
        include: {
          permissions: {
            include: {
              feature: {
                select: { id: true, name: true },
              },
            },
          },
        },
      });

      return {
        ...newRole,
        createdAt: newRole.createdAt.toISOString(),
        updatedAt: newRole.updatedAt.toISOString(),
      };
    });
  },

  updateRole: async (id: string, data: UpdateRoleInput) => {
    const { permissions, ...roleDetails } = data;

    return await prisma.$transaction(async (tx) => {
      await tx.role.update({
        where: { id },
        data: roleDetails,
      });

      if (permissions) {
        await tx.roleFeature.deleteMany({
          where: { roleId: id },
        });

        if (permissions.length > 0) {
          await tx.roleFeature.createMany({
            data: permissions.map((p) => ({
              roleId: id,
              featureId: p.featureId,
              canCreate: p.canCreate,
              canRead: p.canRead,
              canUpdate: p.canUpdate,
              canDelete: p.canDelete,
              canPrint: p.canPrint,
            })),
          });
        }
      }

      const updatedRole = await tx.role.findUniqueOrThrow({
        where: { id },
        include: {
          permissions: {
            include: { feature: true },
          },
        },
      });

      return {
        ...updatedRole,
        createdAt: updatedRole.createdAt.toISOString(),
        updatedAt: updatedRole.updatedAt.toISOString(),
      };
    });
  },

  getMyRole: async (userId: string) => {
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: userId },
      include: {
        role: {
          include: {
            permissions: {
              include: {
                feature: { select: { id: true, name: true } },
              },
            },
          },
        },
      },
    });

    return {
      roleName: user.role.name,
      permissions: user.role.permissions.map((p) => ({
        featureId: p.feature.id,
        featureName: p.feature.name,
        canCreate: p.canCreate,
        canRead: p.canRead,
        canUpdate: p.canUpdate,
        canDelete: p.canDelete,
        canPrint: p.canPrint,
      })),
    };
  },

  deleteRole: async (id: string) => {
    const role = await prisma.role.findUniqueOrThrow({
      where: { id },
    });

    if (PROTECTED_ROLES.includes(role.name)) {
      throw new DeleteSystemError();
    }

    const deletedRole = await prisma.role.delete({
      where: { id },
    });

    return {
      ...deletedRole,
      createdAt: deletedRole.createdAt.toISOString(),
      updatedAt: deletedRole.updatedAt.toISOString(),
    };
  },
};
