import { Context } from "elysia";
import z, { ZodType } from "zod";
type ElysiaSet = Context["set"];

export const successResponse = <T, E>(
  set: ElysiaSet,
  data: T,
  message: string = "Success",
  code: number = 200,
  extras?: E,
) => {
  set.status = code;

  return {
    error: false,
    code,
    message,
    data,
    ...extras,
  } as {
    error: boolean;
    code: number;
    message: string;
    data: T;
  } & E;
};

export const errorResponse = (
  set: ElysiaSet,
  code: number,
  message: string,
  issues: unknown = null,
) => {
  set.status = code;

  return {
    error: true,
    code,
    message,
    issues,
  };
};

export const createResponseSchema = <T extends ZodType>(schema: T) =>
  z.object({
    error: z.boolean().default(false),
    code: z.number(),
    message: z.string(),
    data: z.union([schema, z.null()]),
  });

export const createErrorSchema = (schema: ZodType = z.any()) =>
  z.object({
    error: z.boolean().default(true),
    code: z.number(),
    message: z.string(),
    issues: z.union([schema, z.null()]),
  });

export const PaginationSchema = z.object({
  page: z
    .preprocess(
      (val) => (val === undefined ? undefined : Number(val)),
      z
        .number()
        .min(1, { message: "Page number must be at least 1" })
        .default(1),
    )
    .optional(),

  limit: z
    .preprocess(
      (val) => (val === undefined ? undefined : Number(val)),
      z
        .number()
        .min(1, { message: "Limit must be between 1 and 100" })
        .max(100, { message: "Limit must be between 1 and 100" })
        .default(10),
    )
    .optional(),
});

export const createPaginatedResponseSchema = <T extends ZodType>(
  itemSchema: T,
) =>
  z.object({
    error: z.boolean(),
    code: z.number(),
    message: z.string(),
    data: itemSchema,
    pagination: z.object({
      total: z.number(),
      page: z.number(),
      limit: z.number(),
      totalPages: z.number(),
    }),
  });
