import { RbacService } from "./service";
import { RbacModel } from "./model";
import {
  CreateFeatureSchema,
  CreateRoleSchema,
  FeatureParamSchema,
  GetFeaturesQuerySchema,
  GetRolesOptionsQuerySchema,
  GetRolesQuerySchema,
  RoleParamSchema,
  UpdateFeatureSchema,
  UpdateRoleSchema,
} from "./schema";
import { errorResponse, successResponse } from "@/libs/response";
import { createBaseApp, createProtectedApp } from "@/libs/base";
import { hasPermission } from "@/middleware/permission";
import { Prisma } from "@generated/prisma";
import {
  DeleteSystemError,
  InvalidFeatureIdError,
  UpdateSystemError,
} from "./error";

const FEATURE_NAME = "RBAC_management";

/**
 * PROTECTED ROUTES
 * These REQUIRE a valid Access Token.
 * 'user' is automatically injected by createProtectedApp().
 */
const protectedRbac = createProtectedApp()
  // -------------------------
  // FEATURES CRUD
  // -------------------------
  .get(
    "/features",
    async ({ set, query, log }) => {
      const { page = 1, limit = 10, search } = query;

      const { features, pagination } = await RbacService.getAllFeatures(
        {
          page,
          limit,
          search,
        },
        log,
      );

      return successResponse(
        set,
        features,
        "Features retrieved successfully",
        200,
        {
          pagination,
        },
      );
    },
    {
      query: GetFeaturesQuerySchema,
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      response: {
        200: RbacModel.getFeatures,
        500: RbacModel.error,
      },
    },
  )
  .post(
    "/features",
    async ({ body, set, log }) => {
      const feature = await RbacService.createFeature(body, log);
      return successResponse(set, feature, "Feature created successfully", 201);
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "create"),
      body: CreateFeatureSchema,
      response: {
        201: RbacModel.createFeature,
        400: RbacModel.validationError,
        500: RbacModel.error,
      },
    },
  )
  .patch(
    "/features/:id",
    async ({ params: { id }, body, set, log }) => {
      const feature = await RbacService.updateFeature(id, body, log);
      return successResponse(set, feature, "Feature updated successfully");
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "update"),
      params: FeatureParamSchema,
      body: UpdateFeatureSchema,
      response: {
        200: RbacModel.updateFeature,
        400: RbacModel.validationError,
        500: RbacModel.error,
      },
    },
  )
  .delete(
    "/features/:id",
    async ({ params: { id }, set, log }) => {
      const deletedFeature = await RbacService.deleteFeature(id, log);
      return successResponse(
        set,
        deletedFeature,
        "Feature deleted successfully",
      );
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "delete"),
      params: FeatureParamSchema,
      response: {
        200: RbacModel.deleteFeature,
        500: RbacModel.error,
      },
    },
  )

  // -------------------------
  // ROLES CRUD
  // -------------------------
  .get(
    "/roles",
    async ({ query, set, log }) => {
      const { page = 1, limit = 10, search, feature } = query;

      const { roles, pagination } = await RbacService.getAllRoles(
        {
          page,
          limit,
          search,
          feature,
        },
        log,
      );

      return successResponse(set, roles, "Roles retrieved successfully", 200, {
        pagination,
      });
    },
    {
      query: GetRolesQuerySchema,
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      response: {
        200: RbacModel.getRoles,
        500: RbacModel.error,
      },
    },
  )
  .get(
    "/roles/options",
    async ({ query, set, log }) => {
      const { page, limit, search } = query;
      const { roles, pagination } = await RbacService.getRoleOptions(
        {
          page: Number(page) || 1,
          limit: Number(limit) || 10,
          search: search as string | undefined,
        },
        log,
      );
      return successResponse(
        set,
        roles,
        "Roles options retrieved successfully",
        200,
        {
          pagination,
        },
      );
    },
    {
      query: GetRolesOptionsQuerySchema,
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      response: {
        200: RbacModel.getRoleOptions,
        500: RbacModel.error,
      },
    },
  )
  .get(
    "/roles/:id",
    async ({ params: { id }, set, log }) => {
      const role = await RbacService.getRole(id, log);
      return successResponse(set, role, "Role details retrieved successfully");
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      params: RoleParamSchema,
      response: {
        200: RbacModel.getRole,
        404: RbacModel.error,
        500: RbacModel.error,
      },
    },
  )
  .get(
    "/roles/me",
    async ({ user, set, log }) => {
      const myRole = await RbacService.getMyRole(user.id, log);
      return successResponse(set, myRole, "My role retrieved successfully");
    },
    {
      response: {
        200: RbacModel.getMyRole,
        500: RbacModel.error,
      },
    },
  )
  .post(
    "/roles",
    async ({ body, set, log }) => {
      const newRole = await RbacService.createRole(body, log);
      return successResponse(set, newRole, "Role created successfully", 201);
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "create"),
      body: CreateRoleSchema,
      response: {
        201: RbacModel.createRole,
        400: RbacModel.validationError,
        500: RbacModel.error,
      },
    },
  )
  .patch(
    "/roles/:id",
    async ({ params: { id }, body, set, log }) => {
      const updatedRole = await RbacService.updateRole(id, body, log);
      return successResponse(set, updatedRole, "Role updated successfully");
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "update"),
      params: RoleParamSchema,
      body: UpdateRoleSchema,
      response: {
        200: RbacModel.updateRole,
        400: RbacModel.validationError,
        500: RbacModel.error,
      },
    },
  )
  .delete(
    "/roles/:id",
    async ({ params: { id }, set, log }) => {
      const deletedRole = await RbacService.deleteRole(id, log);
      return successResponse(set, deletedRole, "Role deleted successfully");
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "delete"),
      params: RoleParamSchema,
      response: {
        200: RbacModel.deleteRole,
        500: RbacModel.error,
      },
    },
  );

/**
 * EXPORT
 * Combine them into a single plugin under the "/rbac" prefix.
 */
export const rbac = createBaseApp({ tags: ["RBAC"] }).group("/rbac", (app) =>
  app
    .onError(({ error, set }) => {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2003"
      ) {
        const rawField = (error.meta?.field_name as string) || "unknown";
        const match = rawField.match(/_([a-zA-Z0-9]+)_fkey/);
        const fieldName = match ? match[1] : rawField;

        return errorResponse(
          set,
          400,
          `Invalid Reference: The ID provided for '${fieldName}' does not exist.`,
        );
      }

      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2002"
      ) {
        const target = (error.meta?.target as string[])?.join(", ") || "field";
        return errorResponse(
          set,
          409,
          `Duplicate value for unique field: ${target}`,
        );
      }

      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2025"
      ) {
        return errorResponse(set, 404, "Resource not found");
      }

      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2003"
      ) {
        if (error.meta?.field_name?.toString().includes("User_roleId_fkey")) {
          return errorResponse(
            set,
            409,
            "Cannot delete Role: It is currently assigned to one or more users.",
          );
        }

        return errorResponse(set, 400, "Invalid Reference...");
      }

      if (error instanceof DeleteSystemError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: This is a protected system feature and cannot be deleted.",
        );
      }

      if (error instanceof UpdateSystemError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: This is a protected system feature and cannot be updated.",
        );
      }

      if (error instanceof InvalidFeatureIdError) {
        return errorResponse(set, 400, error.message);
      }
    })
    .use(protectedRbac),
);
