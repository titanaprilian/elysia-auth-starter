import { AuthService } from "./service";
import { AuthModel } from "./model";
import { LoginSchema, RefreshTokenSchema, TokenSchema } from "./schema";
import { errorResponse, successResponse } from "@/libs/response";
import { accessJwt, refreshJwt } from "@/plugins/jwt";
import { env } from "@/config/env";
import { parseDuration } from "@/utils/time";
import { authRateLimit } from "@/plugins/rate-limit";
import { createBaseApp, createProtectedApp } from "@/libs/base";

const REFRESH_TOKEN_MAX_AGE = parseDuration(env.JWT_REFRESH_EXPIRES_IN || "7d");

const isProduction = env.NODE_ENV === "production";

const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? ("none" as const) : ("lax" as const),
  path: "/",
  domain: isProduction ? undefined : undefined,
};

const secureCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: isProduction ? ("none" as const) : ("lax" as const),
  path: "/",
};
const publicAuth = createBaseApp()
  .use(authRateLimit)
  .use(accessJwt)
  .use(refreshJwt)
  .post(
    "/login",
    async ({ body, set, cookie, log, accessJwt, refreshJwt }) => {
      const user = await AuthService.login(body, log);

      if (!user) {
        return errorResponse(set, 401, "Invalid email or password");
      }

      const tokenId = await AuthService.createRefreshToken(user.id);

      const accessToken = await accessJwt.sign({
        sub: user.id,
        tv: user.tokenVersion,
      });

      const refreshToken = await refreshJwt.sign({
        sub: user.id,
        tv: user.tokenVersion,
        jti: tokenId,
      });

      cookie.refresh_token.set({
        value: refreshToken,
        ...cookieOptions,
        maxAge: REFRESH_TOKEN_MAX_AGE,
      });

      return successResponse(
        set,
        {
          access_token: accessToken,
          refresh_token: refreshToken,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
          },
        },
        "User login successfully",
        200,
      );
    },
    {
      body: LoginSchema,
      security: [{}], // Public route
      response: {
        200: AuthModel.login,
        400: AuthModel.validationError,
        401: AuthModel.unauthorizedError,
        403: AuthModel.accountDisabledError,
        500: AuthModel.error,
      },
    },
  )
  .post(
    "/refresh",
    async ({ body, set, cookie, log, accessJwt, refreshJwt }) => {
      const incomingRefreshToken =
        cookie.refresh_token.value || body.refresh_token;

      if (!incomingRefreshToken) {
        return errorResponse(set, 400, "Refresh token is missing");
      }

      const payload = await refreshJwt.verify(incomingRefreshToken as string);

      if (
        !payload ||
        !payload.jti ||
        typeof payload.sub !== "string" ||
        typeof payload.tv !== "number"
      ) {
        return errorResponse(set, 401, "Unauthorized");
      }

      const data = await AuthService.refresh({
        refreshToken: payload.jti,
        userId: payload.sub,
        tokenVersion: payload.tv,
        log,
      });

      const newAccessToken = await accessJwt.sign({
        sub: data.user.id,
        tv: data.tokenVersion,
      });

      const newRefreshToken = await refreshJwt.sign({
        sub: data.user.id,
        tv: data.tokenVersion,
        jti: data.refreshToken,
      });

      cookie.refresh_token.set({
        value: newRefreshToken,
        ...cookieOptions,
        maxAge: REFRESH_TOKEN_MAX_AGE,
      });

      return successResponse(
        set,
        {
          access_token: newAccessToken,
          refresh_token: newRefreshToken,
          user: data.user,
        },
        "Token refreshed successfully",
        200,
      );
    },
    {
      body: RefreshTokenSchema,
      security: [{}], // Public route
      response: {
        200: AuthModel.refresh,
        400: AuthModel.validationError,
        500: AuthModel.error,
      },
    },
  )
  .post(
    "/logout",
    async ({ body, set, log, cookie, refreshJwt }) => {
      const incomingRefreshToken =
        cookie.refresh_token.value || body.refresh_token;

      if (incomingRefreshToken) {
        const payload = await refreshJwt.verify(incomingRefreshToken as string);

        if (payload && payload.jti && typeof payload.sub === "string") {
          await AuthService.logout({
            refreshToken: payload.jti,
            userId: payload.sub,
            log,
          });
        }
      }

      cookie.refresh_token.set({
        value: "",
        ...secureCookieOptions,
        maxAge: 0,
      });

      return successResponse(set, null, "Logged out successfully", 200);
    },
    {
      body: TokenSchema,
      response: {
        200: AuthModel.logout,
        401: AuthModel.unauthorizedError,
        500: AuthModel.error,
      },
    },
  );

/**
 * PROTECTED ROUTES
 * These REQUIRE a valid Access Token.
 * 'user' is automatically injected by createProtectedApp().
 */
const protectedAuth = createProtectedApp()
  .use(refreshJwt)
  .post(
    "/logout/all",
    async ({ user, body, log, cookie, set, refreshJwt }) => {
      const incomingRefreshToken =
        cookie.refresh_token.value || body.refresh_token;

      if (!incomingRefreshToken) {
        return errorResponse(
          set,
          400,
          "Refresh token is required to confirm identity",
        );
      }

      const payload = await refreshJwt.verify(incomingRefreshToken as string);

      if (!payload || !payload.jti || typeof payload.sub !== "string") {
        return errorResponse(set, 401, "Invalid refresh token");
      }

      // This prevents User A from using their Access Token to revoke User B's session
      if (payload.sub !== user.id) {
        return errorResponse(set, 403, "Token mismatch");
      }

      await AuthService.logoutAll({
        userId: user.id,
        requestingTokenId: payload.jti,
        log,
      });

      cookie.refresh_token.set({
        value: "",
        ...secureCookieOptions,
        maxAge: 0,
      });

      return successResponse(set, null, "Logged out from all devices", 200);
    },
    {
      body: TokenSchema,
      response: {
        200: AuthModel.logout,
        400: AuthModel.validationError,
        401: AuthModel.unauthorizedError,
        403: AuthModel.accountDisabledError,
        500: AuthModel.error,
      },
    },
  )
  .get(
    "/me",
    async ({ user, log, set }) => {
      const data = await AuthService.me(user.id, log);

      return successResponse(
        set,
        {
          id: data.id,
          email: data.email,
          name: data.name,
          roleName: data.roleName,
          createdAt: data.createdAt,
          updatedAt: data.updatedAt,
        },
        "Data user successfully retrieved",
        200,
      );
    },
    {
      response: {
        200: AuthModel.me,
        404: AuthModel.error,
        500: AuthModel.error,
      },
    },
  );

/**
 * EXPORT
 * Combine them into a single plugin under the "/auth" prefix.
 * Also define the error in here
 */
export const auth = createBaseApp({ tags: ["Auth"] }).group("/auth", (app) =>
  app.use(publicAuth).use(protectedAuth),
);
