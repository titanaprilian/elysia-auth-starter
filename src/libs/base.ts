import { Elysia, type ElysiaConfig } from "elysia";
import { loggerMiddleware } from "@/middleware/logger";
import { authMiddleware } from "@/middleware/auth";
import { errorResponse } from "./response";
import { AccountDisabledError, UnauthorizedError } from "./exceptions";

/**
 * BASE APP
 * Use this for public routes (Login, Register, Webhooks, Health)
 * - Includes: Logger, Error Handling (You can add it in here)
 * - Excludes: Auth checks
 */
export const createBaseApp = <Prefix extends string = "">(
  config?: ElysiaConfig<Prefix>,
) =>
  new Elysia(config)
    .onError(({ code, error, set }) => {
      if (code === "VALIDATION") {
        const issues = error.all.map((issue: any) => {
          let field = "root";

          // 🛡️ Robust Path Handling
          if (Array.isArray(issue.path)) {
            field = issue.path.join(".");
          } else if (typeof issue.path === "string") {
            field = issue.path.startsWith("/")
              ? issue.path.slice(1)
              : issue.path;
          }

          if (!field) field = "root";

          return {
            field,
            message: issue.message || error.message,
          };
        });

        return errorResponse(set, 400, "Validation Error", issues);
      }
    })
    .use(loggerMiddleware)
    .as("scoped");

/**
 * PROTECTED APP
 * Use this for private routes (Profile, Dashboard, Payments)
 * - Includes: Everything in Base App + Auth Checks
 * - Result: 'user' is guaranteed to exist in context
 */
export const createProtectedApp = <Prefix extends string = "">(
  config?: ElysiaConfig<Prefix>,
) =>
  createBaseApp(config)
    .onError(({ error, set }) => {
      if (error instanceof UnauthorizedError)
        return errorResponse(set, 401, error.message);
      if (error instanceof AccountDisabledError)
        return errorResponse(set, 403, error.message);
    })
    .guard({
      detail: {
        security: [
          {
            bearerAuth: [],
          },
        ],
      },
    })
    .use(authMiddleware)
    .as("scoped");
