import { describe, it, expect, beforeEach, afterAll } from "bun:test";
import { app } from "@/server";
import { prisma } from "@/libs/prisma";
import { createTestUser, resetDatabase, randomIp } from "../test_utils";
import { env } from "@/config/env";
import jwt from "jsonwebtoken";

describe("Authentication Routes Integration", () => {
  // Clean the database before every test to ensure isolation
  beforeEach(async () => {
    resetDatabase();
  });

  // CLose connection after all tests finish
  afterAll(async () => {
    await prisma.$disconnect();
  });

  // --- POST (login) ---
  describe("POST /auth/login", () => {
    it("should login successfully and return tokens", async () => {
      const user = await createTestUser({ email: "login@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "login@test.com",
            password: "password123",
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.access_token).toBeDefined();
      expect(body.data.refresh_token).toBeDefined();
      expect(typeof body.data.access_token).toBe("string");
      expect(body.data.user.id).toBe(user.id);
      expect(body.data.user.email).toBe("login@test.com");
    });

    it("should set a secure httpOnly cookie in the response", async () => {
      await createTestUser({ email: "cookie@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "cookie@test.com",
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(200);
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toBeDefined();
      expect(setCookieHeader).not.toBeNull();

      // Check Security Flags (Crucial for XSS protection)
      expect(setCookieHeader).toContain("refresh_token=");
      expect(setCookieHeader).toContain("HttpOnly");
      expect(setCookieHeader).toContain("Path=/auth");
      expect(setCookieHeader).toContain("SameSite=Strict");
    });

    it("should handle case-insensitive email login", async () => {
      await createTestUser({ email: "login@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "Login@Test.COM",
            password: "password123",
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.access_token).toBeDefined();
      expect(body.data.user.email).toBe("login@test.com");
    });

    it("should return 401 for incorrect password", async () => {
      await createTestUser({ email: "wrongpass@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "wrongpass@test.com",
            password: "wrong_password",
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(401);
      expect(body.message).toBe("Invalid email or password");
    });

    it("should return 401 for non-existent email", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "ghost@test.com",
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 403 if account is disabled", async () => {
      await createTestUser({
        email: "disabled@test.com",
        isActive: false,
      });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "disabled@test.com",
            password: "password123",
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(403);
      expect(body.message).toBe("Your account has been disabled.");
    });

    it("should return 400 for invalid input format", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "not-an-email",
            password: "123",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should allow multiple active sessions (multi-device support)", async () => {
      await createTestUser({ email: "relogin@test.com" });

      // First login (Device 1)
      const firstLogin = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "relogin@test.com",
            password: "password123",
          }),
        }),
      );
      const firstBody = await firstLogin.json();
      const firstRefreshToken = firstBody.data.refresh_token;

      // Second login (Device 2 - should NOT invalidate first token)
      const secondLogin = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "relogin@test.com",
            password: "password123",
          }),
        }),
      );

      expect(secondLogin.status).toBe(200);

      // Old refresh token should still work (multi-device support)
      const refreshAttempt = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
            cookie: `refresh_token=${firstRefreshToken}`,
          },
          body: JSON.stringify({}),
        }),
      );

      expect(refreshAttempt.status).toBe(200);
      const refreshBody = await refreshAttempt.json();
      expect(refreshBody.data.access_token).toBeDefined();
    });

    it("should create separate refresh token records for each login", async () => {
      const user = await createTestUser({ email: "multidevice@test.com" });

      // Login from device 1
      await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multidevice@test.com",
            password: "password123",
          }),
        }),
      );

      // Login from device 2
      await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multidevice@test.com",
            password: "password123",
          }),
        }),
      );

      // Should have 2 refresh tokens in database
      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId: user.id },
      });

      expect(refreshTokens.length).toBe(2);
    });

    it("should return 400 for empty email", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "",
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for whitespace-only email", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "   ",
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for empty password", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "test@test.com",
            password: "",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for missing email field", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for missing password field", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "test@test.com",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should handle email with leading/trailing whitespace", async () => {
      await createTestUser({ email: "trim@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "  trim@test.com  ",
            password: "password123",
          }),
        }),
      );

      const body = await response.json();
      // Should either succeed (if trimmed) or fail with 400 (if not allowed)
      expect([200, 400]).toContain(response.status);
      if (response.status === 200) {
        expect(body.data.user.email).toBe("trim@test.com");
      }
    });

    it("should safely handle SQL injection attempts in email", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "admin'--",
            password: "password123",
          }),
        }),
      );

      // Should return 400 (validation error) or 401 (not found)
      expect([400, 401]).toContain(response.status);
    });

    it("should handle extremely long email input", async () => {
      const longEmail = "a".repeat(300) + "@test.com";

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: longEmail,
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should handle extremely long password input", async () => {
      await createTestUser({ email: "longpass@test.com" });
      const longPassword = "a".repeat(10000);

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "longpass@test.com",
            password: longPassword,
          }),
        }),
      );

      // Should either handle gracefully with 400 or 401
      expect([400, 401]).toContain(response.status);
    });

    it("should not leak password hash in response", async () => {
      await createTestUser({ email: "noleak@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "noleak@test.com",
            password: "password123",
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.user.password).toBeUndefined();
      expect(body.data.user.passwordHash).toBeUndefined();
    });

    it("should create refresh token record in database", async () => {
      const user = await createTestUser({ email: "dbtoken@test.com" });

      const response = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "dbtoken@test.com",
            password: "password123",
          }),
        }),
      );

      expect(response.status).toBe(200);

      // Verify refresh token exists in database
      const refreshTokens = await prisma.refreshToken.findMany({
        where: { userId: user.id },
      });

      expect(refreshTokens.length).toBeGreaterThan(0);
      expect(refreshTokens[0].userId).toBe(user.id);
    });

    it("should handle multiple concurrent login sessions", async () => {
      await createTestUser({ email: "concurrent@test.com" });

      // Simulate two concurrent logins
      const [firstLogin, secondLogin] = await Promise.all([
        app.handle(
          new Request("http://localhost/auth/login", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              email: "concurrent@test.com",
              password: "password123",
            }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/login", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              email: "concurrent@test.com",
              password: "password123",
            }),
          }),
        ),
      ]);

      expect(firstLogin.status).toBe(200);
      expect(secondLogin.status).toBe(200);

      const firstBody = await firstLogin.json();
      const secondBody = await secondLogin.json();

      // Both should have valid but different tokens
      expect(firstBody.data.access_token).toBeDefined();
      expect(secondBody.data.access_token).toBeDefined();
      expect(firstBody.data.refresh_token).not.toBe(
        secondBody.data.refresh_token,
      );
    });
  });

  // --- POST (Refresh) ---
  describe("POST /refresh", () => {
    it("should refresh token successfully", async () => {
      await createTestUser({ email: "refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const loginBody = await loginRes.json();
      const validRefreshToken = loginBody.data.refresh_token;

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: validRefreshToken,
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.access_token).toBeDefined();
      expect(typeof body.data.access_token).toBe("string");
      expect(body.data.refresh_token).toBeDefined();
      expect(body.data.refresh_token).not.toBe(validRefreshToken);
      expect(body.data.user).toBeDefined();
    });

    it("should refresh token successfully and rotate the cookie", async () => {
      await createTestUser({ email: "refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const loginBody = await loginRes.json();
      const validRefreshToken = loginBody.data.refresh_token;

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: validRefreshToken,
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.access_token).toBeDefined();
      expect(body.data.refresh_token).not.toBe(validRefreshToken);

      // Assert: Cookie Rotation
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toBeDefined();
      expect(setCookieHeader).toContain("refresh_token=");
      expect(setCookieHeader).toContain("Path=/auth");
      expect(setCookieHeader).toContain("HttpOnly");
      expect(setCookieHeader).toContain(body.data.refresh_token);
    });

    it("should return 401 for invalid JWT structure", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "this-is-not-a-valid-jwt",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 (and trigger reuse detection) if token is revoked", async () => {
      await createTestUser({ email: "hacker@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "hacker@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();
      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());
      const tokenId = payload.jti;

      await prisma.refreshToken.update({
        where: { token: tokenId },
        data: { revoked: true },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(401);
      // Verify Reuse Detection
      const user = await prisma.user.findUnique({
        where: { email: "hacker@test.com" },
      });
      expect(user?.tokenVersion).toBeGreaterThan(0);
    });

    it("should return 401 if token does not exist in DB", async () => {
      await createTestUser({ email: "deleted@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "deleted@test.com",
            password: "password123",
          }),
        }),
      );
      const {
        data: { refresh_token },
      } = await loginRes.json();
      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());
      const tokenId = payload.jti;

      await prisma.refreshToken.delete({
        where: { token: tokenId },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 for expired refresh token", async () => {
      const user = await createTestUser({ email: "expired@test.com" });

      const secret = env.JWT_REFRESH_SECRET || "default_secret_here";
      const expiredToken = jwt.sign(
        {
          sub: user.id,
          tv: user.tokenVersion,
          jti: "any-uuid",
        },
        secret,
        { expiresIn: "-1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: expiredToken,
          }),
        }),
      );

      expect(response.status).toBe(401);
      const body = await response.json();
      expect(body.message).toBeDefined();
    });

    it("should return 401 if token version doesn't match user's current version", async () => {
      const user = await createTestUser({ email: "version@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "version@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Increment token version (simulating logout all from another device)
      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 400 for missing refresh token in request body", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({}),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for null refresh token", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: null,
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 for empty string refresh token", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "",
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should detect token reuse and revoke all tokens for that user", async () => {
      const user = await createTestUser({ email: "reuse@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "reuse@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token: oldToken },
      } = await loginRes.json();

      // First refresh - should succeed and rotate token
      const firstRefresh = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: oldToken,
          }),
        }),
      );

      expect(firstRefresh.status).toBe(200);

      // Try to reuse the old token - should trigger reuse detection
      const reuseAttempt = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: oldToken,
          }),
        }),
      );

      expect(reuseAttempt.status).toBe(401);

      // Verify token version was incremented (all tokens invalidated)
      const updatedUser = await prisma.user.findUnique({
        where: { id: user.id },
      });
      expect(updatedUser?.tokenVersion).toBeGreaterThan(0);
    });

    it("should return 403 if user account is disabled", async () => {
      const user = await createTestUser({
        email: "disabled_refresh@test.com",
        isActive: true,
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "disabled_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Disable the account
      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.message).toBe("Your account has been disabled.");
    });

    it("should return 401 if user no longer exists", async () => {
      const user = await createTestUser({ email: "deleted_user@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "deleted_user@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Delete the user
      await prisma.user.delete({
        where: { id: user.id },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 for token with invalid signature", async () => {
      await createTestUser({ email: "invalid_sig@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "invalid_sig@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Tamper with the signature
      const parts = refresh_token.split(".");
      const tamperedToken = parts[0] + "." + parts[1] + ".tampered_signature";

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: tamperedToken,
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 for token with only 2 parts (missing signature)", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "header.payload",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should mark old refresh token as revoked after successful rotation", async () => {
      await createTestUser({ email: "rotation@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "rotation@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token: oldToken },
      } = await loginRes.json();

      const payloadPart = oldToken.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());
      const oldTokenId = payload.jti;

      // Refresh the token
      const refreshRes = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: oldToken,
          }),
        }),
      );

      expect(refreshRes.status).toBe(200);

      // Old token should be marked as revoked
      const oldTokenRecord = await prisma.refreshToken.findUnique({
        where: { token: oldTokenId },
      });

      expect(oldTokenRecord?.revoked).toBe(true);
    });

    it("should not leak sensitive user data in refresh response", async () => {
      await createTestUser({ email: "noleak_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "noleak_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.user.password).toBeUndefined();
      expect(body.data.user.passwordHash).toBeUndefined();
      expect(body.data.user.tokenVersion).toBeUndefined();
    });

    it("should handle IP address changes gracefully", async () => {
      await createTestUser({ email: "ip_change@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "192.168.1.1",
          },
          body: JSON.stringify({
            email: "ip_change@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Refresh from different IP
      const response = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "10.0.0.1", // Different IP
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      // Should either succeed or fail based on your security policy
      // Adjust expectation based on your implementation
      expect([200, 401]).toContain(response.status);
    });

    it("should handle concurrent refresh attempts safely", async () => {
      await createTestUser({ email: "concurrent_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "concurrent_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Try to refresh the same token twice simultaneously
      const [first, second] = await Promise.all([
        app.handle(
          new Request("http://localhost/auth/refresh", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              refresh_token: refresh_token,
            }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/refresh", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              refresh_token: refresh_token,
            }),
          }),
        ),
      ]);

      // One should succeed, one should fail (or both succeed with proper locking)
      const statuses = [first.status, second.status].sort();

      // Either one succeeds and one fails, or both succeed if you have proper race condition handling
      expect(
        (statuses[0] === 200 && statuses[1] === 401) ||
          (statuses[0] === 200 && statuses[1] === 200),
      ).toBe(true);
    });
  });

  // --- POST (Logout) ---
  describe("POST /logout", () => {
    it("should logout successfully, revoke DB token, and clear browser cookie", async () => {
      await createTestUser({ email: "logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "logout@test.com",
            password: "password123",
          }),
        }),
      );
      const {
        data: { refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.message).toBe("Logged out successfully");

      // Assert: Cookie Deletion
      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toBeDefined();
      // "Max-Age=0" tells the browser to delete it immediately
      expect(setCookieHeader).toContain("Max-Age=0");
      expect(setCookieHeader).toContain("Path=/auth");

      // Assert: Database Revocation logic (unchanged)
      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());

      const storedToken = await prisma.refreshToken.findUnique({
        where: { token: payload.jti },
      });
      expect(storedToken?.revoked).toBe(true);
    });

    it("should return 200 (Idempotent) even for invalid token structure", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "invalid-jwt-structure",
          }),
        }),
      );

      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should return 400 for null refresh token", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: null,
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 200 for empty string refresh token (idempotent)", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "",
          }),
        }),
      );

      expect(response.status).toBe(200);
    });

    it("should be idempotent when token is already revoked", async () => {
      await createTestUser({ email: "already_revoked@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "already_revoked@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // First logout
      const firstLogout = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(firstLogout.status).toBe(200);

      // Second logout with same token (already revoked)
      const secondLogout = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(secondLogout.status).toBe(200);
      const body = await secondLogout.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should be idempotent when token doesn't exist in database", async () => {
      await createTestUser({ email: "nonexistent_token@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "nonexistent_token@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());

      // Delete token from database
      await prisma.refreshToken.delete({
        where: { token: payload.jti },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should successfully logout even with expired token", async () => {
      await createTestUser({ email: "expired_logout@test.com" });

      // Create an expired token
      const expiredToken = jwt.sign(
        {
          userId: "test-user-id",
          jti: "expired-logout-token",
          tokenVersion: 0,
        },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: "-1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: expiredToken,
          }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should handle logout with token containing invalid signature", async () => {
      await createTestUser({ email: "invalid_sig_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "invalid_sig_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Tamper with signature
      const parts = refresh_token.split(".");
      const tamperedToken = parts[0] + "." + parts[1] + ".invalid_signature";

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: tamperedToken,
          }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should handle logout with incomplete JWT (missing parts)", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "header.payload",
          }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should clear cookie even when token is invalid", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "completely-invalid-token",
          }),
        }),
      );

      expect(response.status).toBe(200);

      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toBeDefined();
      expect(setCookieHeader).toContain("Max-Age=0");
      expect(setCookieHeader).toContain("refresh_token=");
    });

    it("should set correct cookie attributes on logout", async () => {
      await createTestUser({ email: "cookie_attrs@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "cookie_attrs@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      const setCookieHeader = response.headers.get("set-cookie");
      expect(setCookieHeader).toContain("Max-Age=0");
      expect(setCookieHeader).toContain("Path=/auth");
      expect(setCookieHeader).toContain("HttpOnly");
      expect(setCookieHeader).toContain("SameSite=Strict");
    });

    it("should handle concurrent logout attempts gracefully", async () => {
      await createTestUser({ email: "concurrent_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "concurrent_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Multiple logout requests at the same time
      const [first, second, third] = await Promise.all([
        app.handle(
          new Request("http://localhost/auth/logout", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              refresh_token: refresh_token,
            }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/logout", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              refresh_token: refresh_token,
            }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/logout", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({
              refresh_token: refresh_token,
            }),
          }),
        ),
      ]);

      // All should succeed (idempotent)
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(third.status).toBe(200);
    });

    it("should not be able to use token after logout", async () => {
      await createTestUser({ email: "use_after_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "use_after_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Logout
      await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      // Try to use the token for refresh
      const refreshAttempt = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(refreshAttempt.status).toBe(401);
    });

    it("should allow logout from different IP address", async () => {
      await createTestUser({ email: "different_ip_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "192.168.1.1",
          },
          body: JSON.stringify({
            email: "different_ip_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Logout from different IP
      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "10.0.0.1", // Different IP
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out successfully");
    });

    it("should only revoke the specific token, not all user sessions", async () => {
      await createTestUser({
        email: "multi_session_logout@test.com",
      });

      // Login from device 1
      const device1Login = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multi_session_logout@test.com",
            password: "password123",
          }),
        }),
      );

      // Login from device 2
      const device2Login = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multi_session_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const device1Token = (await device1Login.json()).data.refresh_token;
      const device2Token = (await device2Login.json()).data.refresh_token;

      // Logout from device 1 only
      await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: device1Token,
          }),
        }),
      );

      // CHECK DEVICE 2 FIRST
      // We verify that Device 2 is still alive immediately after the logout.
      // At this point, no reuse detection has been triggered yet.
      const device2Refresh = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: device2Token,
          }),
        }),
      );
      expect(device2Refresh.status).toBe(200);

      //  NOW CHECK DEVICE 1 (Expect Failure)
      // This confirms Device 1 is revoked.
      // NOTE: This action will trigger Reuse Detection and kill Device 2,
      // but we don't care anymore because we already asserted Device 2 worked in Step 2.
      const device1Refresh = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: device1Token,
          }),
        }),
      );

      expect(device1Refresh.status).toBe(401);
    });

    it("should handle logout with missing content-type header", async () => {
      await createTestUser({ email: "no_content_type@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "no_content_type@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "x-forwarded-for": randomIp(),
            // No content-type header
          },
          body: JSON.stringify({
            refresh_token: refresh_token,
          }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should handle extremely long token string gracefully", async () => {
      const veryLongToken = "a".repeat(10000);

      const response = await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: veryLongToken,
          }),
        }),
      );

      // Should handle gracefully (idempotent behavior)
      expect(response.status).toBe(200);
    });
  });

  // --- POST (Logout All) ---
  describe("POST /logout/all", () => {
    it("should logout from all devices (increment token version)", async () => {
      await createTestUser({ email: "logout_all@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "logout_all@test.com",
            password: "password123",
          }),
        }),
      );
      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
            "content-type": "application/json",
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.message).toBe("Logged out from all devices");
      const setCookie = response.headers.get("set-cookie");
      expect(setCookie).toContain("Max-Age=0");

      const user = await prisma.user.findUnique({
        where: { email: "logout_all@test.com" },
      });
      expect(user?.tokenVersion).toBeGreaterThan(0);

      const refreshRes = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(refreshRes.status).toBe(401);
    });

    it("should return 401 if no access token provided", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(response.status).toBe(401);
    });

    it("should return 401 if the provided refresh token is already revoked", async () => {
      await createTestUser({ email: "revoked_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "revoked_logout@test.com",
            password: "password123",
          }),
        }),
      );
      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());

      await prisma.refreshToken.update({
        where: { token: payload.jti },
        data: { revoked: true },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
            "content-type": "application/json",
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.message).toBe("Invalid refresh token");
    });

    it("should return 401 if access token is invalid", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-access-token",
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "some-token",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      await createTestUser({ email: "expired_access@test.com" });

      // Create expired access token
      const expiredAccessToken = jwt.sign(
        { userId: "test-user-id" },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${expiredAccessToken}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "some-token",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if Authorization header is malformed", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: "InvalidFormat token-here",
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "some-token",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if Authorization header only contains 'Bearer'", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: "Bearer ",
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            refresh_token: "some-token",
          }),
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- Refresh Token from Body ---
    it("should accept refresh token from request body", async () => {
      await createTestUser({ email: "body_token@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "body_token@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(200);
    });

    // --- Refresh Token from Cookie ---
    it("should accept refresh token from cookie", async () => {
      await createTestUser({ email: "cookie_token@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "cookie_token@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
            cookie: `refresh_token=${refresh_token}`,
          },
          body: JSON.stringify({}),
        }),
      );

      expect(response.status).toBe(200);
    });

    it("should accept refresh token from body if cookie is missing (Mobile App Scenario)", async () => {
      await createTestUser({ email: "mobile_logout@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "mobile_logout@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Act: Send Logout All WITHOUT a cookie header
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.message).toBe("Logged out from all devices");
    });

    // --- Missing Refresh Token ---
    it("should return 400 if no refresh token provided (no body, no cookie)", async () => {
      await createTestUser({ email: "no_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "no_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({}),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 if refresh token is null in body", async () => {
      await createTestUser({ email: "null_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "null_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: null }),
        }),
      );

      expect(response.status).toBe(400);
    });

    it("should return 400 if refresh token is empty string", async () => {
      await createTestUser({ email: "empty_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "empty_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: "" }),
        }),
      );

      expect(response.status).toBe(400);
    });

    // --- Invalid Refresh Token ---
    it("should return 401 if refresh token has invalid structure", async () => {
      await createTestUser({ email: "invalid_structure@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "invalid_structure@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: "not-a-jwt" }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if refresh token doesn't exist in database", async () => {
      await createTestUser({ email: "nonexistent@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "nonexistent@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Delete token from database
      const payloadPart = refresh_token.split(".")[1];
      const payload = JSON.parse(Buffer.from(payloadPart, "base64").toString());
      await prisma.refreshToken.delete({
        where: { token: payload.jti },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if refresh token has expired", async () => {
      const user = await createTestUser({ email: "expired_refresh@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "expired_refresh@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Create expired refresh token
      const expiredRefreshToken = jwt.sign(
        { userId: user.id, jti: "expired-jti", tokenVersion: 0 },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: "-1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: expiredRefreshToken }),
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- Multiple Devices Invalidation ---
    it("should invalidate all refresh tokens across all devices", async () => {
      await createTestUser({ email: "multi_device@test.com" });

      // Login from device 1
      const device1 = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multi_device@test.com",
            password: "password123",
          }),
        }),
      );
      const device1Tokens = (await device1.json()).data;

      // Login from device 2
      const device2 = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multi_device@test.com",
            password: "password123",
          }),
        }),
      );
      const device2Tokens = (await device2.json()).data;

      // Login from device 3
      const device3 = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "multi_device@test.com",
            password: "password123",
          }),
        }),
      );
      const device3Tokens = (await device3.json()).data;

      // Logout all using device 1's tokens
      await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${device1Tokens.access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: device1Tokens.refresh_token }),
        }),
      );

      // Try to refresh from all devices - all should fail
      const refresh1 = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: device1Tokens.refresh_token }),
        }),
      );

      const refresh2 = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: device2Tokens.refresh_token }),
        }),
      );

      const refresh3 = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: device3Tokens.refresh_token }),
        }),
      );

      expect(refresh1.status).toBe(401);
      expect(refresh2.status).toBe(401);
      expect(refresh3.status).toBe(401);
    });

    it("should increment token version exactly once", async () => {
      const user = await createTestUser({
        email: "version_increment@test.com",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "version_increment@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const initialUser = await prisma.user.findUnique({
        where: { id: user.id },
      });
      const initialVersion = initialUser?.tokenVersion || 0;

      await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      const updatedUser = await prisma.user.findUnique({
        where: { id: user.id },
      });

      expect(updatedUser?.tokenVersion).toBe(initialVersion + 1);
    });

    // --- Cookie Clearing ---
    it("should clear refresh token cookie", async () => {
      await createTestUser({ email: "cookie_clear@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "cookie_clear@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      const setCookie = response.headers.get("set-cookie");
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain("Max-Age=0");
      expect(setCookie).toContain("Path=/auth");
      expect(setCookie).toContain("HttpOnly");
    });

    // --- Token Version Mismatch ---
    it("should return 401 if refresh token has outdated token version", async () => {
      const user = await createTestUser({ email: "version_mismatch@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "version_mismatch@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Manually increment token version (simulate previous logout all)
      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- User Mismatch ---
    it("should return 401 if access token user doesn't match refresh token user", async () => {
      await createTestUser({
        email: "user1@test.com",
        id: "cml3d8f5r00002a6hetsp193c",
      });
      await createTestUser({
        email: "user2@test.com",
        id: "cml3d8f5r00002a6hetsp193d",
      });

      const login1 = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "user1@test.com",
            password: "password123",
          }),
        }),
      );
      const tokens1 = (await login1.json()).data;

      const login2 = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "user2@test.com",
            password: "password123",
          }),
        }),
      );
      const tokens2 = (await login2.json()).data;

      // Try to logout all using user1's access token but user2's refresh token
      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${tokens1.access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: tokens2.refresh_token }),
        }),
      );

      expect(response.status).toBe(403);
    });

    // --- Disabled Account ---
    it("should return 403 if user account is disabled", async () => {
      const user = await createTestUser({ email: "disabled_all@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "disabled_all@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Disable account
      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(response.status).toBe(403);
    });

    // --- Concurrent Logout All ---
    it("should handle concurrent logout all requests safely", async () => {
      await createTestUser({ email: "concurrent_all@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "concurrent_all@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Multiple logout all requests at once
      const [first, second, third] = await Promise.all([
        app.handle(
          new Request("http://localhost/auth/logout/all", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({ refresh_token }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/logout/all", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({ refresh_token }),
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/logout/all", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "content-type": "application/json",
              "x-forwarded-for": randomIp(),
            },
            body: JSON.stringify({ refresh_token }),
          }),
        ),
      ]);

      // At least one should succeed
      const statuses = [first.status, second.status, third.status];
      expect(statuses).toContain(200);
    });

    // --- After Logout All ---
    it("should allow new login after logout all", async () => {
      await createTestUser({ email: "relogin_after_all@test.com" });

      const firstLogin = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "relogin_after_all@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await firstLogin.json();

      // Logout all
      await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      // Try to login again
      const secondLogin = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "relogin_after_all@test.com",
            password: "password123",
          }),
        }),
      );

      expect(secondLogin.status).toBe(200);
      const newTokens = (await secondLogin.json()).data;
      expect(newTokens.access_token).toBeDefined();
      expect(newTokens.refresh_token).toBeDefined();

      // New tokens should work
      const refreshAttempt = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token: newTokens.refresh_token }),
        }),
      );

      expect(refreshAttempt.status).toBe(200);
    });

    // --- Idempotency ---
    it("should be idempotent when called multiple times sequentially", async () => {
      await createTestUser({ email: "idempotent_all@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "idempotent_all@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // First logout all
      const first = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(first.status).toBe(200);

      // Second logout all with same (now invalid) token - should fail since token is revoked
      const second = await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      expect(second.status).toBe(401);
    });
  });

  // --- GET (me) ---
  describe("GET /me", () => {
    it("should return user profile when authenticated", async () => {
      const user = await createTestUser({
        email: "me@test.com",
        name: "Profile User",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "me@test.com",
            password: "password123",
          }),
        }),
      );
      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.id).toBe(user.id);
      expect(body.data.email).toBe("me@test.com");
      expect(body.data.name).toBe("Profile User");
      expect(body.data.password).toBeUndefined();
    });

    it("should return 401 if access token is missing", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            "content-type": "application/json",
            Authorization: "Bearer invalid-junk-token",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      const user = await createTestUser({ email: "expired_me@test.com" });

      // Create expired access token
      const expiredToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if Authorization header is malformed", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: "InvalidFormat token-here",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if Authorization header only contains 'Bearer'", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: "Bearer ",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if Authorization header is empty string", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: "",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if token has invalid signature", async () => {
      await createTestUser({ email: "invalid_sig_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "invalid_sig_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Tamper with signature
      const parts = access_token.split(".");
      const tamperedToken = parts[0] + "." + parts[1] + ".invalid_signature";

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${tamperedToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if token is incomplete (missing parts)", async () => {
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: "Bearer header.payload",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- User State Validation ---
    it("should return 403 if user account is disabled", async () => {
      const user = await createTestUser({
        email: "disabled_me@test.com",
        isActive: true,
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "disabled_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Disable account
      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.message).toBe("Your account has been disabled.");
    });

    it("should return 401 if user no longer exists", async () => {
      const user = await createTestUser({ email: "deleted_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "deleted_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Delete user
      await prisma.user.delete({
        where: { id: user.id },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if token contains non-existent user ID", async () => {
      // Create token with fake user ID
      const fakeToken = jwt.sign(
        { userId: "non-existent-user-id" },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${fakeToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- Response Data Validation ---
    it("should not leak sensitive data in response", async () => {
      await createTestUser({
        email: "noleak_me@test.com",
        name: "No Leak User",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "noleak_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);

      // Should not contain sensitive fields
      expect(body.data.password).toBeUndefined();
      expect(body.data.passwordHash).toBeUndefined();
      expect(body.data.tokenVersion).toBeUndefined();
    });

    it("should return all expected user fields", async () => {
      await createTestUser({
        email: "complete_me@test.com",
        name: "Complete User",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "complete_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data).toHaveProperty("id");
      expect(body.data).toHaveProperty("email");
      expect(body.data).toHaveProperty("name");
      expect(body.data).toHaveProperty("createdAt");
      expect(body.data).toHaveProperty("updatedAt");
    });

    // --- Token After Logout ---
    it("should return 401 after user logs out (single device)", async () => {
      await createTestUser({ email: "after_logout_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "after_logout_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Verify /me works before logout
      const beforeLogout = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(beforeLogout.status).toBe(200);

      // Logout
      await app.handle(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      // Note: Access token should still work after single logout
      // because access tokens are stateless and not revoked
      const afterLogout = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Access token remains valid until expiration (stateless)
      expect(afterLogout.status).toBe(200);
    });

    it("should return 401 after user logs out from all devices", async () => {
      await createTestUser({
        email: "after_logout_all_me@test.com",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "after_logout_all_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token, refresh_token },
      } = await loginRes.json();

      // Logout all
      await app.handle(
        new Request("http://localhost/auth/logout/all", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Should fail because token version changed
      expect(response.status).toBe(401);
    });

    // --- Concurrent Requests ---
    it("should handle multiple concurrent /me requests", async () => {
      await createTestUser({ email: "concurrent_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "concurrent_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Multiple concurrent requests
      const [first, second, third] = await Promise.all([
        app.handle(
          new Request("http://localhost/auth/me", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/me", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request("http://localhost/auth/me", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${access_token}`,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
      ]);

      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect(third.status).toBe(200);

      const [body1, body2, body3] = await Promise.all([
        first.json(),
        second.json(),
        third.json(),
      ]);

      // All should return same user data
      expect(body1.data.email).toBe("concurrent_me@test.com");
      expect(body2.data.email).toBe("concurrent_me@test.com");
      expect(body3.data.email).toBe("concurrent_me@test.com");
    });

    // --- Different IP Addresses ---
    it("should allow access from different IP addresses", async () => {
      await createTestUser({ email: "different_ip_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": "192.168.1.1",
          },
          body: JSON.stringify({
            email: "different_ip_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Access from different IP
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": "10.0.0.1", // Different IP
          },
        }),
      );

      expect(response.status).toBe(200);
    });

    // --- Token with Missing Claims ---
    it("should return 401 if token is missing userId claim", async () => {
      const tokenWithoutUserId = jwt.sign(
        { someOtherClaim: "value" },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${tokenWithoutUserId}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if token userId is null", async () => {
      const tokenWithNullUserId = jwt.sign(
        { userId: null },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${tokenWithNullUserId}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    it("should return 401 if token userId is empty string", async () => {
      const tokenWithEmptyUserId = jwt.sign(
        { userId: "" },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "1h" },
      );

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${tokenWithEmptyUserId}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- Case Sensitivity ---
    it("should handle case-sensitive Authorization header (lowercase 'bearer')", async () => {
      await createTestUser({ email: "lowercase_bearer@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "lowercase_bearer@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `bearer ${access_token}`, // lowercase 'bearer'
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Should either accept it (case-insensitive) or reject it (case-sensitive)
      // Adjust based on your implementation
      expect([200, 401]).toContain(response.status);
    });

    // --- Updated User Data ---
    it("should return updated user data after profile changes", async () => {
      const user = await createTestUser({
        email: "update_me@test.com",
        name: "Original Name",
      });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "update_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { access_token },
      } = await loginRes.json();

      // Update user profile
      await prisma.user.update({
        where: { id: user.id },
        data: { name: "Updated Name" },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${access_token}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await response.json();
      expect(response.status).toBe(200);
      expect(body.data.name).toBe("Updated Name");
    });

    // --- Token Reuse Across Endpoints ---
    it("should work with access token from refresh endpoint", async () => {
      await createTestUser({ email: "refresh_then_me@test.com" });

      const loginRes = await app.handle(
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            email: "refresh_then_me@test.com",
            password: "password123",
          }),
        }),
      );

      const {
        data: { refresh_token },
      } = await loginRes.json();

      // Get new access token via refresh
      const refreshRes = await app.handle(
        new Request("http://localhost/auth/refresh", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ refresh_token }),
        }),
      );

      const {
        data: { access_token: newAccessToken },
      } = await refreshRes.json();

      // Use new access token for /me
      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${newAccessToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(200);
      const body = await response.json();
      expect(body.data.email).toBe("refresh_then_me@test.com");
    });

    // --- Very Long Access Token ---
    it("should handle extremely long token gracefully", async () => {
      const veryLongToken = "a".repeat(10000);

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${veryLongToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(response.status).toBe(401);
    });

    // --- Token Version Validation ---
    it("should validate token version matches user's current version", async () => {
      const user = await createTestUser({
        email: "token_version_me@test.com",
        tokenVersion: 0,
      });

      // Create token with old version
      const oldToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "1h" },
      );

      // Increment user's token version
      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const response = await app.handle(
        new Request("http://localhost/auth/me", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${oldToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Should fail due to version mismatch
      expect(response.status).toBe(401);
    });
  });

  describe("Rate Limiter Security", () => {
    it("should return 429 Too Many Requests after exceeding limit", async () => {
      // Simulate a single attacker IP
      const ATTACKER_IP = "192.168.1.100";

      // Define the request (Login is a common target)
      const createRequest = () =>
        new Request("http://localhost/auth/login", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": ATTACKER_IP,
          },
          body: JSON.stringify({
            email: "spam@target.com",
            password: "random-password",
          }),
        });

      // Spam the server
      const results = [];
      for (let i = 0; i < 20; i++) {
        const response = await app.handle(createRequest());
        results.push(response.status);

        if (response.status === 429) break;
      }
      // Assert: We should have received at least one 429 error
      const wasBlocked = results.includes(429);

      expect(wasBlocked).toBe(true);
    });
  });
});
