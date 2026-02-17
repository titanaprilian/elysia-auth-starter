import { UserService } from "./service";
import { UserModel } from "./model";
import {
  CreateUserSchema,
  GetUsersQuerySchema,
  UpdateUserSchema,
  UserParamSchema,
} from "./schema";
import { errorResponse, successResponse } from "@/libs/response";
import { createBaseApp, createProtectedApp } from "@/libs/base";
import { hasPermission } from "@/middleware/permission";
import { Prisma } from "@generated/prisma";
import { DeleteSystemError } from "../rbac/error";
import { CreateSystemError, DeleteSelfError, UpdateSystemError } from "./error";

const FEATURE_NAME = "user_management";

const protectedUser = createProtectedApp()
  .get(
    "/",
    async ({ query, set }) => {
      const { page = 1, limit = 10, isActive, roleId, search } = query;

      const { users, pagination } = await UserService.getUsers({
        page,
        limit,
        isActive,
        roleId,
        search,
      });

      return successResponse(set, users, "Users retrieved successfully", 200, {
        pagination,
      });
    },
    {
      query: GetUsersQuerySchema,
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      response: {
        200: UserModel.users,
        500: UserModel.error,
      },
    },
  )
  .post(
    "/",
    async ({ body, set }) => {
      const data = await UserService.createUser(body);
      return successResponse(set, data, "User Succesfully Created", 201);
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "create"),
      body: CreateUserSchema,
      response: {
        201: UserModel.user,
        400: UserModel.validationError,
        409: UserModel.error,
        500: UserModel.error,
      },
    },
  )
  .get(
    "/:id",
    async ({ params, set }) => {
      const user = await UserService.getUser(params.id);
      if (!user) {
        return errorResponse(set, 404, "User Not Found");
      }

      return successResponse(set, user, "User details retrieved", 200);
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "read"),
      params: UserParamSchema,
      response: {
        200: UserModel.user,
        404: UserModel.error,
        500: UserModel.error,
      },
    },
  )
  .patch(
    "/:id",
    async ({ body, params, set }) => {
      const updatedUser = await UserService.updateUser(params.id, body);

      console.log(updatedUser);
      return successResponse(
        set,
        updatedUser,
        "User updated successfully",
        200,
      );
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "update"),
      params: UserParamSchema,
      body: UpdateUserSchema,
      response: {
        200: UserModel.user,
        400: UserModel.validationError,
        404: UserModel.error,
        500: UserModel.error,
      },
    },
  )
  .delete(
    "/:id",
    async ({ params, user, set }) => {
      const deletedUser = await UserService.deleteUser(params.id, user.id);
      return successResponse(
        set,
        deletedUser,
        "User Successfully Deleted",
        200,
      );
    },
    {
      beforeHandle: hasPermission(FEATURE_NAME, "delete"),
      params: UserParamSchema,
      response: {
        200: UserModel.deleteResult,
        404: UserModel.error,
        500: UserModel.error,
      },
    },
  );

export const user = createBaseApp({ tags: ["User"] }).group("/users", (app) =>
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

      if (error instanceof DeleteSystemError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: This is a protected user and cannot be deleted",
        );
      }

      if (error instanceof DeleteSelfError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: You cannot delete your own account",
        );
      }

      if (error instanceof CreateSystemError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: You cannot create user with SuperAdmin role more than one",
        );
      }

      if (error instanceof UpdateSystemError) {
        return errorResponse(
          set,
          403,
          "Operation Forbidden: You cannot update user status to inactive with SuperAdmin role",
        );
      }
    })
    .use(protectedUser),
);
