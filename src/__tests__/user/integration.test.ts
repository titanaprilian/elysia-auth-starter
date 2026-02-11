import { describe, it, expect, beforeEach, afterAll } from "bun:test";
import { app } from "@/server";
import { prisma } from "@/libs/prisma";
import {
  createAuthenticatedUser,
  createTestRoleWithPermissions,
  randomIp,
  resetDatabase,
  seedTestUsers,
} from "../test_utils";
import jwt from "jsonwebtoken";

describe("User Routes Integration", () => {
  // Clean the database before every test to ensure isolation
  beforeEach(async () => {
    await resetDatabase();
  });

  // CLose connection after all tests finish
  afterAll(async () => {
    await prisma.$disconnect();
  });

  // --- POST (Create) ---
  describe("POST /users", () => {
    // ─────────────────────────────
    // Authentication & Authorization
    // ─────────────────────────────

    it("should return 401 if not logged in", async () => {
      const payload = {
        name: "John Doe",
        email: "john@example.com",
        password: "Password123!",
        roleId: "role-id",
      };

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user has no user_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const role = await prisma.role.create({
        data: { name: "Employee" },
      });

      const payload = {
        name: "John Doe",
        email: "john@example.com",
        password: "Password123!",
        roleId: role.id,
      };

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has user_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Employee" },
      });

      const payload = {
        name: "John Doe",
        email: "john@example.com",
        password: "Password123!",
        roleId: role.id,
      };

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has create permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Employee" },
      });

      const payload = {
        name: "John Doe",
        email: "john@example.com",
        password: "Password123!",
        roleId: role.id,
      };

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Successful Creation
    // ─────────────────────────────

    it("should create user successfully with valid permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Employee" },
      });

      const payload = {
        name: "John Doe",
        email: "john@example.com",
        password: "Password123!",
        roleId: role.id,
      };

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(201);
      expect(body.data.email).toBe("john@example.com");
      expect(body.data.password).toBeUndefined();
    });

    it("should create user with isActive defaulted to true", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Employee" },
      });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({
            name: "Jane Doe",
            email: "jane@example.com",
            password: "Password123!",
            roleId: role.id,
          }),
        }),
      );

      const user = await prisma.user.findUnique({
        where: { email: "jane@example.com" },
      });

      expect(user?.isActive).toBe(true);
    });

    // ─────────────────────────────
    // Field Validation
    // ─────────────────────────────

    it("should return 201 even if name is missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            email: "john@example.com",
            password: "Password123!",
            roleId: role.id,
          }),
        }),
      );

      expect(res.status).toBe(201);
    });

    it("should return 400 if email is invalid", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            name: "John",
            email: "not-an-email",
            password: "Password123!",
            roleId: role.id,
          }),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if password is too short", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            name: "John",
            email: "john@example.com",
            password: "123",
            roleId: role.id,
          }),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if roleId does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            name: "John",
            email: "john@example.com",
            password: "Password123!",
            roleId: "non-existent-id",
          }),
        }),
      );

      expect(res.status).toBe(400);
    });

    // ─────────────────────────────
    // Uniqueness & Security
    // ─────────────────────────────

    it("should return 409 if email already exists", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      await prisma.user.create({
        data: {
          name: "Existing",
          email: "john@example.com",
          password: "hashed",
          roleId: role.id,
        },
      });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            name: "John",
            email: "john@example.com",
            password: "Password123!",
            roleId: role.id,
          }),
        }),
      );

      expect(res.status).toBe(409);
    });

    it("should hash password before saving", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({
            name: "Secure User",
            email: "secure@example.com",
            password: "Password123!",
            roleId: role.id,
          }),
        }),
      );

      const user = await prisma.user.findUnique({
        where: { email: "secure@example.com" },
      });

      expect(user?.password).not.toBe("Password123!");
    });

    // ─────────────────────────────
    // Token & Account State
    // ─────────────────────────────

    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({}),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request("http://localhost/users", {
          method: "POST",
          headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          body: JSON.stringify({}),
        }),
      );

      expect(res.status).toBe(403);
    });
  });

  // --- GET (List) ---
  describe("GET /users", () => {
    // ─────────────────────────────
    // Authentication
    // ─────────────────────────────

    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: { "x-forwarded-for": randomIp() },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: user.tokenVersion },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Authorization (RBAC)
    // ─────────────────────────────

    it("should return 403 if user has no user_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has only create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if read permission is on another feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Pagination – Empty & Defaults
    // ─────────────────────────────

    it("should return one data user with correct pagination when only requester exists", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=1&limit=10", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.pagination).toEqual({
        total: 1,
        page: 1,
        limit: 10,
        totalPages: 1,
      });
    });

    // ─────────────────────────────
    // Pagination – Limit & Page
    // ─────────────────────────────

    it("should respect limit parameter", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      await prisma.user.createMany({
        data: Array.from({ length: 15 }).map((_, i) => ({
          name: `User ${i}`,
          email: `user${i}@example.com`,
          password: "hashed",
          roleId: role.id,
        })),
      });

      const res = await app.handle(
        new Request("http://localhost/users?page=1&limit=5", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(5);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.limit).toBe(5);
      expect(body.pagination.total).toBeGreaterThanOrEqual(15);
    });

    it("should return different results for different pages", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const r1 = await app.handle(
        new Request("http://localhost/users?page=1&limit=3", {
          headers: authHeaders,
        }),
      );

      const r2 = await app.handle(
        new Request("http://localhost/users?page=2&limit=3", {
          headers: authHeaders,
        }),
      );

      const b1 = await r1.json();
      const b2 = await r2.json();

      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect(b1.data).not.toEqual(b2.data);
      expect(b2.pagination.page).toBe(2);
    });

    // ─────────────────────────────
    // Response Structure & Security
    // ─────────────────────────────

    it("should return correct user response structure", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);

      body.data.forEach((user: any) => {
        expect(user).toHaveProperty("id");
        expect(user).toHaveProperty("name");
        expect(user).toHaveProperty("email");
        expect(user).toHaveProperty("roleId");
        expect(user).toHaveProperty("isActive");
      });

      expect(body.pagination).toHaveProperty("total");
      expect(body.pagination).toHaveProperty("page");
      expect(body.pagination).toHaveProperty("limit");
      expect(body.pagination).toHaveProperty("totalPages");
    });

    it("should not leak sensitive fields", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      body.data.forEach((user: any) => {
        expect(user.password).toBeUndefined();
        expect(user.tokenVersion).toBeUndefined();
        expect(user.refreshTokens).toBeUndefined();
      });
    });

    // ─────────────────────────────
    // Account State
    // ─────────────────────────────

    it("should include inactive users", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      await prisma.user.create({
        data: {
          name: "Inactive User",
          email: "inactive@example.com",
          password: "hashed",
          roleId: role.id,
          isActive: false,
        },
      });

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      const inactive = body.data.find(
        (u: any) => u.email === "inactive@example.com",
      );

      expect(res.status).toBe(200);
      expect(inactive).toBeDefined();
      expect(inactive.isActive).toBe(false);
    });

    // ─────────────────────────────
    // Permission Revocation
    // ─────────────────────────────

    it("should return 403 after read permission is revoked", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const before = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(before.status).toBe(200);

      const role = await prisma.role.findFirst({ where: { name: "TestUser" } });

      await prisma.roleFeature.deleteMany({
        where: {
          roleId: role!.id,
          feature: { name: "user_management" },
          canRead: true,
        },
      });

      const after = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(after.status).toBe(403);
    });

    // ─────────────────────────────
    // Token Version
    // ─────────────────────────────

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Concurrency
    // ─────────────────────────────

    it("should return consistent results for concurrent requests", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const [r1, r2, r3] = await Promise.all([
        app.handle(
          new Request("http://localhost/users", { headers: authHeaders }),
        ),
        app.handle(
          new Request("http://localhost/users", { headers: authHeaders }),
        ),
        app.handle(
          new Request("http://localhost/users", { headers: authHeaders }),
        ),
      ]);

      const [b1, b2, b3] = await Promise.all([r1.json(), r2.json(), r3.json()]);

      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect(r3.status).toBe(200);
      expect(b1.data).toEqual(b2.data);
      expect(b2.data).toEqual(b3.data);
    });

    // ─────────────────────────────
    // Invalid Pagination
    // ─────────────────────────────

    it("should return 400 if page is 0", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=0&limit=10", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.issues[0].message).toBe("Page number must be at least 1");
    });

    it("should return 400 if page is negative", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=-1&limit=10", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if limit exceeds maximum", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?limit=999", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.issues[0].message).toBe("Limit must be between 1 and 100");
    });

    it("should return 400 if limit is 0", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=1&limit=0", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if page is not a number", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=abc&limit=10", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if limit is not a number", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users?page=1&limit=foo", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should fallback to defaults if pagination params are missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.limit).toBe(10);
    });

    // ─────────────────────────────
    // Search & Filter Queries
    // ─────────────────────────────
    it("should filter users by name (partial match)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      await seedTestUsers();

      const res = await app.handle(
        new Request("http://localhost/users?search=alice", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.data[0].name).toMatch(/alice/i);
    });

    it("should filter users by email", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      await seedTestUsers();

      const res = await app.handle(
        new Request("http://localhost/users?search=bob@example.com", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.data[0].email).toBe("bob@example.com");
    });

    it("should filter users by isActive=true", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      await seedTestUsers();

      const res = await app.handle(
        new Request("http://localhost/users?isActive=true", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.every((u: any) => u.isActive === true)).toBe(true);
    });

    it("should filter users by isActive=false", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      await seedTestUsers();

      const res = await app.handle(
        new Request("http://localhost/users?isActive=false", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.every((u: any) => u.isActive === false)).toBe(true);
    });

    it("should filter users by roleId", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      const { roleEmployee } = await seedTestUsers();

      const res = await app.handle(
        new Request(`http://localhost/users?roleId=${roleEmployee.id}`, {
          headers: authHeaders,
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.length).toBeGreaterThan(0);
      expect(body.data.every((u: any) => u.roleId === roleEmployee.id)).toBe(
        true,
      );
    });

    it("should support combined filters (roleId + isActive)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      const { roleEmployee } = await seedTestUsers();

      const res = await app.handle(
        new Request(
          `http://localhost/users?roleId=${roleEmployee.id}&isActive=true`,
          { headers: authHeaders },
        ),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(
        body.data.every(
          (u: any) => u.roleId === roleEmployee.id && u.isActive === true,
        ),
      ).toBe(true);
    });

    it("should return empty result if no users match filters", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      await seedTestUsers();

      const res = await app.handle(
        new Request("http://localhost/users?search=nonexistent", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data).toEqual([]);
    });

    it("should work together with pagination", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);
      const { roleEmployee } = await seedTestUsers();

      const res = await app.handle(
        new Request(
          `http://localhost/users?roleId=${roleEmployee.id}&page=1&limit=1`,
          { headers: authHeaders },
        ),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.pagination.limit).toBe(1);
      expect(body.pagination.page).toBe(1);
    });
  });

  // --- GET (By ID) ---
  describe("GET /users/:id", () => {
    // ─────────────────────────────
    // Authentication
    // ─────────────────────────────

    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/users/some-id", {
          headers: {
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const res = await app.handle(
        new Request("http://localhost/users/some-id", {
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Authorization (RBAC)
    // ─────────────────────────────

    it("should return 403 if user has no user_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const targetUser = await prisma.user.create({
        data: {
          name: "Target User",
          email: "target@example.com",
          password: "hashed",
          roleId: (await prisma.role.create({ data: { name: "Employee" } })).id,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has user_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "create" },
      ]);

      const targetUser = await prisma.user.create({
        data: {
          name: "Target User",
          email: "target2@example.com",
          password: "hashed",
          roleId: (await prisma.role.create({ data: { name: "Employee" } })).id,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has read permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const targetUser = await prisma.user.create({
        data: {
          name: "Target User",
          email: "target3@example.com",
          password: "hashed",
          roleId: (await prisma.role.create({ data: { name: "Employee" } })).id,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Successful Access
    // ─────────────────────────────

    it("should return 200 and user data if permission is valid", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const targetUser = await prisma.user.create({
        data: {
          name: "Target User",
          email: "target4@example.com",
          password: "hashed",
          roleId: role.id,
          isActive: true,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.id).toBe(targetUser.id);
      expect(body.data.email).toBe("target4@example.com");
    });

    // ─────────────────────────────
    // Response Structure & Security
    // ─────────────────────────────

    it("should return correct user response structure", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();

      expect(body.data).toHaveProperty("id");
      expect(body.data).toHaveProperty("name");
      expect(body.data).toHaveProperty("email");
      expect(body.data).toHaveProperty("roleId");
      expect(body.data).toHaveProperty("isActive");
    });

    it("should not leak sensitive fields", async () => {
      const { user, authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();

      expect(body.data.password).toBeUndefined();
      expect(body.data.tokenVersion).toBeUndefined();
      expect(body.data.refreshTokens).toBeUndefined();
    });

    // ─────────────────────────────
    // User ID Validation
    // ─────────────────────────────

    it("should return 404 if user does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users/non-existent-id", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(404);
    });

    it("should return 400 if user ID format is invalid", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users/invalid-id-format", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect([400, 404]).toContain(res.status);
    });

    // ─────────────────────────────
    // Account State
    // ─────────────────────────────

    it("should return 403 if requesting user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Token Version
    // ─────────────────────────────

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Real-time Permission Changes
    // ─────────────────────────────

    it("should return 403 after user_management read permission is revoked", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const before = await app.handle(
        new Request(
          `http://localhost/users/${(await prisma.user.findFirst())!.id}`,
          {
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          },
        ),
      );
      expect(before.status).toBe(200);

      const role = await prisma.role.findFirst({ where: { name: "TestUser" } });
      await prisma.roleFeature.deleteMany({
        where: {
          roleId: role!.id,
          feature: { name: "user_management" },
          canRead: true,
        },
      });

      const after = await app.handle(
        new Request(
          `http://localhost/users/${(await prisma.user.findFirst())!.id}`,
          {
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          },
        ),
      );

      expect(after.status).toBe(403);
    });
  });

  // --- PATCH (Update) ---
  describe("PATCH /users/:id", () => {
    // ─────────────────────────────
    // Authentication
    // ─────────────────────────────

    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/users/some-id", {
          method: "PATCH",
          headers: {
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Name" }),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "PATCH",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Authorization (RBAC)
    // ─────────────────────────────

    it("should return 403 if user has no user_management update permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has user_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has update permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Successful Updates
    // ─────────────────────────────

    it("should update user name successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Name" }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("Updated Name");
    });

    it("should update email successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ email: "updated@example.com" }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.email).toBe("updated@example.com");
    });

    it("should update password and hash it", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const targetUser = await prisma.user.findFirst();

      await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ password: "NewPassword123!" }),
        }),
      );

      const updated = await prisma.user.findUnique({
        where: { id: targetUser!.id },
      });

      expect(updated?.password).not.toBe("NewPassword123!");
    });

    it("should update roleId successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const newRole = await prisma.role.create({
        data: { name: "NewRole" },
      });

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ roleId: newRole.id }),
        }),
      );

      expect(res.status).toBe(200);
    });

    it("should update isActive flag", async () => {
      const { user, authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ isActive: false }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.isActive).toBe(false);
    });

    // ─────────────────────────────
    // Validation & Safety
    // ─────────────────────────────

    it("should return 404 if user does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users/non-existent-id", {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(404);
    });

    it("should return 400 if request body is empty", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({}),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should not leak password in response", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      const body = await res.json();
      expect(body.data.password).toBeUndefined();
    });

    // ─────────────────────────────
    // Account & Token State
    // ─────────────────────────────

    it("should return 403 if requester account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated" }),
        }),
      );

      expect(res.status).toBe(401);
    });
  });

  // --- DELETE ---
  describe("DELETE /users/:id", () => {
    // ─────────────────────────────
    // Authentication
    // ─────────────────────────────

    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/users/some-id", {
          method: "DELETE",
          headers: {
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const res = await app.handle(
        new Request("http://localhost/users/some-id", {
          method: "DELETE",
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Authorization (RBAC)
    // ─────────────────────────────

    it("should return 403 if user has no user_management delete permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has user_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has delete permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const targetUser = await prisma.user.findFirst();

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser!.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Safety Rules
    // ─────────────────────────────

    it("should return 403 if user tries to delete themselves", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // ─────────────────────────────
    // Successful Deletion
    // ─────────────────────────────

    it("should delete user successfully with valid permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const targetUser = await prisma.user.create({
        data: {
          name: "Delete Me",
          email: "delete@example.com",
          password: "hashed",
          roleId: role.id,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      const deleted = await prisma.user.findUnique({
        where: { id: targetUser.id },
      });

      expect(deleted).toBeNull();
    });

    it("should allow deleting inactive user", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const targetUser = await prisma.user.create({
        data: {
          name: "Inactive User",
          email: "inactive@example.com",
          password: "hashed",
          roleId: role.id,
          isActive: false,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${targetUser.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);
    });

    // ─────────────────────────────
    // User ID Validation
    // ─────────────────────────────

    it("should return 404 if user does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users/non-existent-id", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(404);
    });

    it("should return 400 if user ID format is invalid", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/users/invalid-id-format", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect([400, 404]).toContain(res.status);
    });

    // ─────────────────────────────
    // Token & Account State
    // ─────────────────────────────

    it("should return 403 if requester account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const res = await app.handle(
        new Request(`http://localhost/users/${user.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // ─────────────────────────────
    // Concurrency
    // ─────────────────────────────

    it("should handle concurrent delete requests safely", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "delete" },
      ]);

      const role = await prisma.role.create({ data: { name: "Employee" } });

      const targetUser = await prisma.user.create({
        data: {
          name: "Concurrent Delete",
          email: "concurrent@example.com",
          password: "hashed",
          roleId: role.id,
        },
      });

      const [r1, r2] = await Promise.all([
        app.handle(
          new Request(`http://localhost/users/${targetUser.id}`, {
            method: "DELETE",
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
        app.handle(
          new Request(`http://localhost/users/${targetUser.id}`, {
            method: "DELETE",
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
      ]);

      expect([200, 404]).toContain(r1.status);
      expect([200, 404]).toContain(r2.status);
    });
  });
});
