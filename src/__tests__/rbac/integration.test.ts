import { describe, it, expect, beforeEach, afterAll } from "bun:test";
import { app } from "@/server";
import { prisma } from "@/libs/prisma";
import {
  createAuthenticatedUser,
  createTestRoleWithPermissions,
  createTestUser,
  randomIp,
  resetDatabase,
  seedTestFeatures,
  seedTestRoles,
} from "../test_utils";
import jwt from "jsonwebtoken";

describe("RBAC Integration", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  // --- GET (features) ---
  describe("GET /rbac/features", () => {
    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return test user permission list initially", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data[0].name).toBe("RBAC_management");
    });

    it("should return 403 if user role has no RBAC_management permission at all", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // Don't assign any RBAC_management permission

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role only has RBAC_management create but not read", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" }, // Has create, but not read
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role only has RBAC_management update but not read", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role only has RBAC_management delete but not read", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role has permission on different feature, not RBAC_management", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" }, // Wrong feature
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Access with Read Permission ---
    it("should return 200 and feature list when role has RBAC_management read", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(Array.isArray(body.data)).toBe(true);
    });

    // --- Feature List Content ---
    it("should return all existing features in the system", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      // Create additional features via another role setup
      await createTestRoleWithPermissions("AdminUser", [
        { featureName: "user_management", action: "read" },
        { featureName: "order_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);

      const featureNames = body.data.map((f: any) => f.name);
      expect(featureNames).toContain("RBAC_management");
      expect(featureNames).toContain("user_management");
      expect(featureNames).toContain("order_management");
    });

    // --- Response Structure ---
    it("should return correct response structure for each feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);

      body.data.forEach((feature: any) => {
        expect(feature).toHaveProperty("id");
        expect(feature).toHaveProperty("name");
        expect(typeof feature.id).toBe("string");
        expect(typeof feature.name).toBe("string");
      });
    });

    it("should not leak sensitive internal data in feature response", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);

      body.data.forEach((feature: any) => {
        expect(feature.roleId).toBeUndefined();
        expect(feature.userId).toBeUndefined();
        expect(feature.permissions).toBeUndefined();
      });
    });

    // --- Role Isolation ---
    it("should allow access for AdminUser role with RBAC_management read", async () => {
      const adminRole = await createTestRoleWithPermissions("AdminUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const { authHeaders } = await createAuthenticatedUser({
        roleId: adminRole.id,
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);
    });

    it("should deny access for AdminUser role without RBAC_management read", async () => {
      const adminRole = await prisma.role.upsert({
        where: { name: "AdminUser" },
        update: {},
        create: { name: "AdminUser", description: "Admin role for tests" },
      });

      const { authHeaders } = await createAuthenticatedUser({
        roleId: adminRole.id,
      });
      await createTestRoleWithPermissions("AdminUser", [
        { featureName: "user_management", action: "read" }, // Not RBAC_management
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token has tampered signature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      const token = authHeaders.Authorization.split(" ")[1];
      const parts = token.split(".");
      const tamperedToken = parts[0] + "." + parts[1] + ".tampered";

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            Authorization: `Bearer ${tamperedToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 401 if user no longer exists", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      await prisma.user.delete({
        where: { id: user.id },
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Token Version ---
    it("should return 401 if token version is outdated after logout all", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Real-time Permission Changes ---
    it("should return 403 after RBAC_management read permission is revoked", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      // Verify access works first
      const beforeRes = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(beforeRes.status).toBe(200);

      // Remove RBAC_management read permission
      const role = await prisma.role.findFirst({ where: { name: "TestUser" } });
      await prisma.roleFeature.deleteMany({
        where: {
          roleId: role!.id,
          feature: { name: "RBAC_management" },
          canRead: true,
        },
      });

      // Should now be denied
      const afterRes = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(afterRes.status).toBe(403);
    });

    it("should gain access after RBAC_management read permission is granted", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions yet

      // Verify access is denied first
      const beforeRes = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(beforeRes.status).toBe(403);

      // Grant RBAC_management read
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      // Should now be allowed
      const afterRes = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(afterRes.status).toBe(200);
    });

    // --- Concurrent Requests ---
    it("should handle multiple concurrent requests consistently", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const [res1, res2, res3] = await Promise.all([
        app.handle(
          new Request("http://localhost/rbac/features", {
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request("http://localhost/rbac/features", {
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request("http://localhost/rbac/features", {
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
      ]);

      const [body1, body2, body3] = await Promise.all([
        res1.json(),
        res2.json(),
        res3.json(),
      ]);

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
      expect(res3.status).toBe(200);
      expect(body1.data).toEqual(body2.data);
      expect(body2.data).toEqual(body3.data);
    });

    // -- Pagination & Search
    it("should return paginated feature list with default params", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(Array.isArray(body.data)).toBe(true);

      expect(body.pagination).toMatchObject({
        page: 1,
        limit: 10,
      });

      expect(body.pagination.total).toBeGreaterThanOrEqual(5);
      expect(body.pagination.totalPages).toBeGreaterThanOrEqual(1);
    });

    it("should respect limit parameter", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features?limit=2", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(2);
      expect(body.pagination.limit).toBe(2);
    });

    it("should return different results for different pages", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const r1 = await app.handle(
        new Request("http://localhost/rbac/features?page=1&limit=2", {
          headers: authHeaders,
        }),
      );

      const r2 = await app.handle(
        new Request("http://localhost/rbac/features?page=2&limit=2", {
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

    it("should filter features by name (partial match)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features?search=order", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.data[0].name).toBe("order_management");
    });

    it("should return empty array if search does not match any feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features?search=nonexistent", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual([]);
      expect(body.pagination.total).toBe(0);
    });

    it("should combine search and pagination correctly", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request(
          "http://localhost/rbac/features?search=management&limit=1&page=2",
          { headers: authHeaders },
        ),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.pagination.page).toBe(2);
      expect(body.pagination.limit).toBe(1);
      expect(body.pagination.total).toBeGreaterThanOrEqual(3);
    });

    it("should return 400 if page is 0", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features?page=0", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if limit exceeds maximum", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features?limit=999", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should fallback to defaults if pagination params are missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestFeatures();

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.limit).toBe(10);
    });
  });

  // --- POST (features) ---
  describe("POST /rbac/features", () => {
    it("should return 401 if not logged in", async () => {
      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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

    it("should return 403 if user has no RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions assigned

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" }, // Wrong action
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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
        { featureName: "user_management", action: "create" }, // Wrong feature
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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

    // --- Successful Creation ---
    it("should create feature successfully with all permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: true,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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
      expect(body.data.name).toBe("order_management");
      expect(body.data.description).toBe("Order management feature");
      expect(body.message).toBe("Feature created successfully");
    });

    it("should create feature successfully with partial permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: false,
          canRead: true,
          canUpdate: false,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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
      expect(body.data.name).toBe("order_management");
    });

    it("should create feature successfully with all permissions false", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: false,
          canRead: false,
          canUpdate: false,
          canDelete: false,
          canPrint: false,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    // --- Name Validation ---
    it("should return 400 if name is missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: null,
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is empty string", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is only whitespace", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "   ",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is less than 3 characters", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "ab",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name exceeds 50 characters", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "a".repeat(51),
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should trim whitespace from name", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "  order_management  ",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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
      expect(body.data.name).toBe("order_management");
    });

    it("should accept name at minimum length (3 characters)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "abc",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    it("should accept name at maximum length (50 characters)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "a".repeat(50),
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    // --- Duplicate Feature Name ---
    it("should return 409 if feature name already exists", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      // Create first feature
      await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(409);
    });

    it("should handle case-insensitive duplicate feature names", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "ORDER_MANAGEMENT",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      // Should either return 409 or 201 depending on case-sensitivity implementation
      expect([201, 409]).toContain(res.status);
    });

    // --- Description Field ---
    it("should create feature successfully without description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    it("should create feature successfully with null description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: null,
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    it("should create feature successfully with empty description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    // --- defaultPermissions Validation ---
    it("should return 400 if defaultPermissions is missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if defaultPermissions is null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: null,
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if defaultPermissions is not an object", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: "not-an-object",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 201 even if canCreate is missing (default to false)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );
      expect(res.status).toBe(201);

      const savedFeature = await prisma.feature.findUnique({
        where: { name: "order_management" },
      });
      expect(savedFeature).not.toBeNull();

      const savedRoleFeature = await prisma.roleFeature.findFirst({
        where: {
          featureId: savedFeature!.id,
        },
      });
      expect(savedRoleFeature).not.toBeNull();
      expect(savedRoleFeature?.canCreate).toBe(false);
    });

    it("should return 201 if canRead is missing (default to false)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );
      expect(res.status).toBe(201);

      const savedFeature = await prisma.feature.findUnique({
        where: { name: "order_management" },
      });
      expect(savedFeature).not.toBeNull();

      const savedRoleFeature = await prisma.roleFeature.findFirst({
        where: {
          featureId: savedFeature!.id,
        },
      });
      expect(savedRoleFeature).not.toBeNull();
      expect(savedRoleFeature?.canRead).toBe(false);
    });

    it("should return 201 even if canUpdate is missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);

      const savedFeature = await prisma.feature.findUnique({
        where: { name: "order_management" },
      });
      expect(savedFeature).not.toBeNull();

      const savedRoleFeature = await prisma.roleFeature.findFirst({
        where: {
          featureId: savedFeature!.id,
        },
      });
      expect(savedRoleFeature).not.toBeNull();
      expect(savedRoleFeature?.canUpdate).toBe(false);
    });

    it("should return 201 if canDelete is missing (default to false)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);

      const savedFeature = await prisma.feature.findUnique({
        where: { name: "order_management" },
      });
      expect(savedFeature).not.toBeNull();

      const savedRoleFeature = await prisma.roleFeature.findFirst({
        where: {
          featureId: savedFeature!.id,
        },
      });
      expect(savedRoleFeature).not.toBeNull();
      expect(savedRoleFeature?.canDelete).toBe(false);
    });

    it("should return 201 if canPrint is missing (default to false)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);

      const savedFeature = await prisma.feature.findUnique({
        where: { name: "order_management" },
      });
      expect(savedFeature).not.toBeNull();

      const savedRoleFeature = await prisma.roleFeature.findFirst({
        where: {
          featureId: savedFeature!.id,
        },
      });
      expect(savedRoleFeature).not.toBeNull();
      expect(savedRoleFeature?.canPrint).toBe(false);
    });

    it("should return 400 if permission flags are not boolean", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: "yes",
          canRead: 1,
          canUpdate: null,
          canDelete: undefined,
          canPrint: "true",
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Response Validation ---
    it("should return created feature with all expected fields", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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
      expect(body.data).toHaveProperty("id");
      expect(body.data).toHaveProperty("name");
      expect(body.data).toHaveProperty("description");
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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

    // --- Malformed Request ---
    it("should return 400 for invalid JSON body", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: "{ invalid json }",
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 for empty request body", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: "",
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Database Persistence ---
    it("should persist feature to database correctly", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: false,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
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

      // Verify in database
      const dbFeature = await prisma.feature.findUnique({
        where: { id: body.data.id },
      });

      expect(dbFeature).not.toBeNull();
      expect(dbFeature?.name).toBe("order_management");
      expect(dbFeature?.description).toBe("Order management feature");
    });

    // --- Token Version ---
    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const payload = {
        name: "order_management",
        description: "Order management feature",
        defaultPermissions: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          canPrint: true,
        },
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });
  });

  // --- PATCH (features) ---
  describe("PATCH /rbac/features", () => {
    it("should return 401 if not logged in", async () => {
      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user has no RBAC_management update permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions assigned

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" }, // Wrong action
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" }, // Wrong action
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has update permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" }, // Wrong feature
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Update ---
    it("should update feature name successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original description" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("updated_order_management");
      expect(body.data.description).toBe("Original description"); // Unchanged
    });

    it("should update feature description successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original description" },
      });

      const payload = {
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("order_management"); // Unchanged
      expect(body.data.description).toBe("Updated description");
    });

    it("should update both name and description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original description" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("updated_order_management");
      expect(body.data.description).toBe("Updated description");
    });

    it("should update description to null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original description" },
      });

      const payload = {
        description: null,
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.description).toBeNull();
    });

    it("should update description to empty string", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original description" },
      });

      const payload = {
        description: "",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(200);
    });

    // --- Feature ID Validation ---
    it("should return 404 if feature does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features/non-existent-id", {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(404);
    });

    it("should return 400 if feature ID is invalid format", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/features/invalid-id-format", {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect([400, 404]).toContain(res.status);
    });

    // --- Name Validation ---
    it("should return 400 if name is empty string", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is only whitespace", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "   ",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is less than 3 characters", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "ab",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name exceeds 50 characters", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "a".repeat(51),
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should trim whitespace from name", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "  updated_order_management  ",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("updated_order_management");
    });

    it("should accept name at minimum length (3 characters)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "abc",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(200);
    });

    it("should accept name at maximum length (50 characters)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "a".repeat(50),
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(200);
    });

    // --- Duplicate Name ---
    it("should return 409 if updated name already exists on another feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      // Create two features
      const feature1 = await prisma.feature.create({
        data: { name: "order_management" },
      });

      await prisma.feature.create({
        data: { name: "user_management" },
      });

      const payload = {
        name: "user_management", // Already exists
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature1.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(409);
    });

    it("should allow updating feature with same name (no change)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "order_management", // Same name
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(200);
    });

    it("should handle case-insensitive duplicate names", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature1 = await prisma.feature.create({
        data: { name: "order_management" },
      });

      await prisma.feature.create({
        data: { name: "user_management" },
      });

      const payload = {
        name: "USER_MANAGEMENT", // Different case
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature1.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      // Should either return 409 or 200 depending on case-sensitivity
      expect([200, 409]).toContain(res.status);
    });

    // --- Empty/No Changes Update ---
    it("should return 400 if request body is empty", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
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

    // --- Response Validation ---
    it("should return updated feature with all expected fields", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data).toHaveProperty("id");
      expect(body.data).toHaveProperty("name");
      expect(body.data).toHaveProperty("description");
      expect(body.data.id).toBe(feature.id);
    });

    // --- Database Persistence ---
    it("should persist changes to database correctly", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original" },
      });

      const payload = {
        name: "updated_order_management",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(200);

      // Verify in database
      const dbFeature = await prisma.feature.findUnique({
        where: { id: feature.id },
      });

      expect(dbFeature?.name).toBe("updated_order_management");
      expect(dbFeature?.description).toBe("Updated description");
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Malformed Request ---
    it("should return 400 for invalid JSON body", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: "{ invalid json }",
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Partial Updates ---
    it("should allow updating only name", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original" },
      });

      const payload = {
        name: "updated_order_management",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("updated_order_management");
      expect(body.data.description).toBe("Original");
    });

    it("should allow updating only description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Original" },
      });

      const payload = {
        description: "New description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("order_management");
      expect(body.data.description).toBe("New description");
    });
  });

  // --- DELETE (features) ---
  describe("DELETE /rbac/features/:id", () => {
    // --- Permission Gate ---
    it("should return 401 if not logged in", async () => {
      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user has no RBAC_management delete permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions assigned

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" }, // Wrong action
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" }, // Wrong action
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management update permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" }, // Wrong action
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
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
        { featureName: "user_management", action: "delete" }, // Wrong feature
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Deletion ---
    it("should delete feature successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Test feature" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.message).toBe("Feature deleted successfully");
    });

    it("should remove feature from database", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify deletion in database
      const dbFeature = await prisma.feature.findUnique({
        where: { id: feature.id },
      });

      expect(dbFeature).toBeNull();
    });

    // --- Feature ID Validation ---
    it("should return 404 if feature does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features/non-existent-id", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(404);
    });

    it("should return 400 if feature ID is invalid format", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features/invalid-id-format", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect([400, 404]).toContain(res.status);
    });

    // --- Idempotency ---
    it("should return 404 when deleting already deleted feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // First delete
      const firstDelete = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(firstDelete.status).toBe(200);

      // Second delete attempt
      const secondDelete = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(secondDelete.status).toBe(404);
    });

    // --- Cascade Deletion / Foreign Key Constraints ---
    it("should delete feature and cascade delete associated permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // Create role with permission on this feature
      const role = await prisma.role.create({
        data: { name: "TestRole" },
      });

      await prisma.roleFeature.create({
        data: {
          roleId: role.id,
          featureId: feature.id,
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          canPrint: false,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify feature is deleted
      const dbFeature = await prisma.feature.findUnique({
        where: { id: feature.id },
      });
      expect(dbFeature).toBeNull();

      // Verify permissions are cascade deleted
      const permissions = await prisma.roleFeature.findMany({
        where: { featureId: feature.id },
      });
      expect(permissions).toHaveLength(0);
    });

    it("should handle deletion when feature has multiple role permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // Create multiple roles with permissions
      const role1 = await prisma.role.create({
        data: { name: "Role1" },
      });
      const role2 = await prisma.role.create({
        data: { name: "Role2" },
      });
      const role3 = await prisma.role.create({
        data: { name: "Role3" },
      });

      await prisma.roleFeature.createMany({
        data: [
          {
            roleId: role1.id,
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
          {
            roleId: role2.id,
            featureId: feature.id,
            canRead: true,
            canCreate: true,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
          {
            roleId: role3.id,
            featureId: feature.id,
            canRead: true,
            canCreate: true,
            canUpdate: true,
            canDelete: false,
            canPrint: false,
          },
        ],
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify all permissions are deleted
      const permissions = await prisma.roleFeature.findMany({
        where: { featureId: feature.id },
      });
      expect(permissions).toHaveLength(0);
    });

    it("should prevent deletion if feature is a system/protected feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      // Get the RBAC_management feature
      const systemFeature = await prisma.feature.findFirstOrThrow({
        where: {
          name: "RBAC_management",
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${systemFeature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.message).toContain("protected system feature");

      // Verify feature still exists
      const dbFeature = await prisma.feature.findUnique({
        where: { id: systemFeature.id },
      });
      expect(dbFeature).not.toBeNull();
    });

    // --- Response Validation ---
    it("should return deleted feature data in response", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management", description: "Test feature" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data).toBeDefined();
      expect(body.data.id).toBe(feature.id);
      expect(body.data.name).toBe("order_management");
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
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
      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token has tampered signature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      const token = authHeaders.Authorization.split(" ")[1];
      const parts = token.split(".");
      const tamperedToken = parts[0] + "." + parts[1] + ".tampered";

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${tamperedToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 401 if user no longer exists", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      await prisma.user.delete({
        where: { id: user.id },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if token version is outdated", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { tokenVersion: { increment: 1 } },
      });

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Concurrent Deletion ---
    it("should handle concurrent deletion attempts safely", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // Attempt to delete concurrently
      const [first, second, third] = await Promise.all([
        app.handle(
          new Request(`http://localhost/rbac/features/${feature.id}`, {
            method: "DELETE",
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request(`http://localhost/rbac/features/${feature.id}`, {
            method: "DELETE",
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
        app.handle(
          new Request(`http://localhost/rbac/features/${feature.id}`, {
            method: "DELETE",
            headers: {
              ...authHeaders,
              "x-forwarded-for": randomIp(),
            },
          }),
        ),
      ]);

      const statuses = [first.status, second.status, third.status].sort();

      // One should succeed (200), others should fail (404)
      const successCount = statuses.filter((s) => s === 200).length;
      const notFoundCount = statuses.filter((s) => s === 404).length;

      expect(successCount).toBe(1);
      expect(notFoundCount).toBe(2);
    });

    // --- Different Users Same Feature ---
    it("should allow different users with permission to delete features", async () => {
      // User 1
      await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      // User 2 with same permission
      const adminRole = await prisma.role.upsert({
        where: { name: "AdminUser" },
        update: {},
        create: { name: "AdminUser", description: "Admin role" },
      });
      const user2 = await createAuthenticatedUser({
        id: "cml3d8f5r00002a6hetsp193c",
        email: "newuser@gmail.com",
        roleId: adminRole.id,
      });
      await createTestRoleWithPermissions("AdminUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // User 2 deletes the feature
      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...user2.authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify deletion
      const dbFeature = await prisma.feature.findUnique({
        where: { id: feature.id },
      });
      expect(dbFeature).toBeNull();
    });

    // --- Feature Still in Use ---
    it("should handle deletion of feature currently assigned to users' roles", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "order_management" },
      });

      // Assign this feature to TestUser role
      const testUserRole = await prisma.role.findFirst({
        where: { name: "TestUser" },
      });

      await prisma.roleFeature.create({
        data: {
          roleId: testUserRole!.id,
          featureId: feature.id,
          canRead: true,
          canCreate: false,
          canUpdate: false,
          canDelete: false,
          canPrint: false,
        },
      });

      // Create a user with this role
      await createTestUser({
        roleId: testUserRole!.id,
        email: "newCreateUser@gmail.com",
        id: "cml3d8f5r00002a6hetsp193c",
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/features/${feature.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Should succeed with cascade deletion
      expect(res.status).toBe(200);

      // Verify feature and permissions are deleted
      const dbFeature = await prisma.feature.findUnique({
        where: { id: feature.id },
      });
      expect(dbFeature).toBeNull();

      const permissions = await prisma.roleFeature.findMany({
        where: { featureId: feature.id },
      });
      expect(permissions).toHaveLength(0);
    });

    // --- Empty or Missing ID ---
    it("should return 404 for empty feature ID", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/features/", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect([404, 405]).toContain(res.status); // 405 if route doesn't match
    });
  });

  // --- GET (roles) ---
  describe("GET /rbac/roles", () => {
    it("should return 401 if not logged in", async () => {
      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user role has no RBAC_management permission at all", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role only has RBAC_management create but not read", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user role has permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Access ---
    it("should return 200 and list of roles when RBAC_management read is granted", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(Array.isArray(body.data)).toBe(true);
    });

    // --- Role List Content ---
    it("should return all roles in the system", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      // Create extra roles
      await prisma.role.create({
        data: { name: "AdminUser", description: "Admin role" },
      });

      await prisma.role.create({
        data: { name: "ManagerUser", description: "Manager role" },
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      const roleNames = body.data.map((r: any) => r.name);

      expect(res.status).toBe(200);
      expect(roleNames).toContain("TestUser");
      expect(roleNames).toContain("AdminUser");
      expect(roleNames).toContain("ManagerUser");
    });

    // --- Response Structure ---
    it("should return correct response structure for each role", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);

      body.data.forEach((role: any) => {
        expect(role).toHaveProperty("id");
        expect(role).toHaveProperty("name");
        expect(role).toHaveProperty("description");
        expect(typeof role.id).toBe("string");
        expect(typeof role.name).toBe("string");
      });
    });

    it("should not leak sensitive internal data in role response", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();

      body.data.forEach((role: any) => {
        expect(role.users).toBeUndefined();
        expect(role.roleFeatures).toBeUndefined();
      });
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Real-time Permission Changes ---
    it("should deny access after RBAC_management read permission is revoked", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const beforeRes = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(beforeRes.status).toBe(200);

      const role = await prisma.role.findFirst({ where: { name: "TestUser" } });
      await prisma.roleFeature.deleteMany({
        where: {
          roleId: role!.id,
          feature: { name: "RBAC_management" },
          canRead: true,
        },
      });

      const afterRes = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(afterRes.status).toBe(403);
    });

    // --- Concurrency ---
    it("should handle concurrent role list requests consistently", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const [r1, r2] = await Promise.all([
        app.handle(
          new Request("http://localhost/rbac/roles", {
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
        app.handle(
          new Request("http://localhost/rbac/roles", {
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
      ]);

      const [b1, b2] = await Promise.all([r1.json(), r2.json()]);

      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);
      expect(b1.data).toEqual(b2.data);
    });

    // -- Pagination --
    it("should return paginated roles with default params", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(Array.isArray(body.data)).toBe(true);

      expect(body.pagination).toMatchObject({
        page: 1,
        limit: 10,
      });

      expect(body.pagination.total).toBeGreaterThanOrEqual(5);
      expect(body.pagination.totalPages).toBeGreaterThanOrEqual(1);
    });

    it("should respect limit parameter", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?limit=2", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(2);
      expect(body.pagination.limit).toBe(2);
    });

    it("should return different roles for different pages", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const r1 = await app.handle(
        new Request("http://localhost/rbac/roles?page=1&limit=2", {
          headers: authHeaders,
        }),
      );

      const r2 = await app.handle(
        new Request("http://localhost/rbac/roles?page=2&limit=2", {
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

    it("should filter roles by name (search)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?search=Admin", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.data[0].name).toBe("AdminUser");
    });

    it("should return empty result when search does not match any role", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?search=nonexistent", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual([]);
      expect(body.pagination.total).toBe(0);
    });

    it("should combine search and pagination correctly", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?search=User&limit=1&page=2", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(1);
      expect(body.pagination.page).toBe(2);
      expect(body.pagination.limit).toBe(1);
      expect(body.pagination.total).toBeGreaterThanOrEqual(4);
    });

    // ─────────────────────────────
    // Invalid Pagination
    // ─────────────────────────────

    it("should return 400 if page is 0", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?page=0", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if limit exceeds maximum", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles?limit=999", {
          headers: authHeaders,
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should fallback to defaults when pagination params are missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);
      await seedTestRoles();

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          headers: authHeaders,
        }),
      );

      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.pagination.page).toBe(1);
      expect(body.pagination.limit).toBe(10);
    });
  });

  // --- POST (roles) ---
  describe("POST /rbac/roles", () => {
    it("should create a role with permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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
      expect(body.data.name).toBe("Support Agent");

      expect(body.data.permissions[0].feature.name).toBe("Settings");
      expect(body.data.permissions[0].canRead).toBe(true);
    });

    it("should return 401 if not logged in", async () => {
      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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

    it("should return 403 if user has no RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions assigned

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" }, // Wrong action
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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
        { featureName: "user_management", action: "create" }, // Wrong feature
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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

    it("should return 400 if name is missing", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is empty string", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is only whitespace", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "   ",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name is null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: null,
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if name exceeds maximum length", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "a".repeat(256), // Assuming max length is 255
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 409 if role name already exists", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      // Create first role
      await prisma.role.create({
        data: {
          name: "Support Agent",
          description: "Existing role",
        },
      });

      const payload = {
        name: "Support Agent", // Duplicate name
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(409);
    });

    it("should create role successfully without description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.name).toBe("Support Agent");
    });

    it("should create role with null description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: null,
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    it("should create role with empty description", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
    });

    it.only("should create role without permissions array and make it all false", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      if (res.status === 400) {
        console.log("Validation Error Details:", JSON.stringify(body, null, 2));
      }

      expect(res.status).toBe(201);
      expect(body.data.permissions.length).toBeGreaterThan(0);
      body.data.permissions.forEach((perm: any) => {
        expect(perm.canCreate).toBe(false);
        expect(perm.canRead).toBe(false);
        expect(perm.canUpdate).toBe(false);
        expect(perm.canDelete).toBe(false);
        expect(perm.canPrint).toBe(false);
      });
    });

    it("should create role with empty permissions array", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      const body = await res.json();
      if (res.status === 400) {
        console.log("Validation Error Details:", JSON.stringify(body, null, 2));
      }
      expect(res.status).toBe(201);
      expect(body.data.permissions).toEqual([]);
    });

    it("should return 400 if permissions is not an array", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: "not-an-array",
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if permission is missing featureId", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if featureId is invalid (non-existent)", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: "non-existent-feature-id",
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 if featureId is null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: null,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should create role with default false for missing action flags", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            // Missing all action flags
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);

      const body = await res.json();
      const perm = body.data.permissions[0];

      // Verify defaults worked
      expect(perm.canRead).toBe(false);
      expect(perm.canCreate).toBe(false);
    });

    it("should return 400 if action flags are not boolean", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: "yes", // Should be boolean
            canCreate: 1,
            canUpdate: null,
            canDelete: undefined,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Multiple Permissions ---
    it("should create role with multiple permissions on different features", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature1 = await prisma.feature.create({
        data: { name: "Settings" },
      });
      const feature2 = await prisma.feature.create({
        data: { name: "Reports" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature1.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
          {
            featureId: feature2.id,
            canRead: true,
            canCreate: true,
            canUpdate: false,
            canDelete: false,
            canPrint: true,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.data.permissions).toHaveLength(2);
    });

    it("should return 400 for duplicate featureId in permissions array", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
          {
            featureId: feature.id, // Duplicate
            canRead: false,
            canCreate: true,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Response Validation ---
    it("should return created role with all expected fields", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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
      expect(body.data).toHaveProperty("id");
      expect(body.data).toHaveProperty("name");
      expect(body.data).toHaveProperty("description");
      expect(body.data).toHaveProperty("permissions");
      expect(body.data).toHaveProperty("createdAt");
      expect(body.data).toHaveProperty("updatedAt");
    });

    it("should include feature details in permission response", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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
      expect(body.data.permissions[0].feature).toBeDefined();
      expect(body.data.permissions[0].feature.id).toBe(feature.id);
      expect(body.data.permissions[0].feature.name).toBe("Settings");
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is invalid", async () => {
      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            Authorization: "Bearer invalid-token",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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

    // --- Malformed Request ---
    it("should return 400 for invalid JSON body", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: "{ invalid json }",
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should return 400 for empty request body", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
          method: "POST",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: "",
        }),
      );

      expect(res.status).toBe(400);
    });

    // --- Role Persistence ---
    it("should persist role to database correctly", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const feature = await prisma.feature.create({
        data: { name: "Settings" },
      });

      const payload = {
        name: "Support Agent",
        description: "Level 1 Support",
        permissions: [
          {
            featureId: feature.id,
            canRead: true,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            canPrint: false,
          },
        ],
      };

      const res = await app.handle(
        new Request("http://localhost/rbac/roles", {
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

      // Verify in database
      const dbRole = await prisma.role.findUnique({
        where: { id: body.data.id },
        include: { permissions: true },
      });

      expect(dbRole).not.toBeNull();
      expect(dbRole?.name).toBe("Support Agent");
      expect(dbRole?.permissions).toHaveLength(1);
    });
  });

  // --- PATCH (roles) ---
  describe("PATCH /rbac/roles", () => {
    it("should return 401 if not logged in", async () => {
      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const payload = {
        name: "Updated Manager",
        description: "Updated description",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user has no RBAC_management update permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const payload = {
        name: "Updated Manager",
      };

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify(payload),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user has update permission on different feature", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "user_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Update ---
    it("should update role name successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager", description: "Original" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("Updated Manager");
      expect(body.data.description).toBe("Original");
    });

    it("should update role description successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager", description: "Original" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ description: "Updated description" }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("Manager");
      expect(body.data.description).toBe("Updated description");
    });

    it("should update description to null", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager", description: "Original" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ description: null }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.description).toBeNull();
    });

    // --- Role ID Validation ---
    it("should return 404 if role does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles/non-existent-id", {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(404);
    });

    // --- Name Validation ---
    it("should return 400 if name is empty string", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "" }),
        }),
      );

      expect(res.status).toBe(400);
    });

    it("should trim whitespace from name", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "  Updated Manager  " }),
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data.name).toBe("Updated Manager");
    });

    // --- Duplicate Name ---
    it("should return 409 if role name already exists", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role1 = await prisma.role.create({ data: { name: "Manager" } });
      await prisma.role.create({ data: { name: "Admin" } });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role1.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Admin" }),
        }),
      );

      expect(res.status).toBe(409);
    });

    // --- Empty Body ---
    it("should return 400 if request body is empty", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
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

    // --- Token / Account State ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const role = await prisma.role.create({
        data: { name: "Manager" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "PATCH",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
          body: JSON.stringify({ name: "Updated Manager" }),
        }),
      );

      expect(res.status).toBe(403);
    });
  });

  // --- DELETE (roles) ---
  describe("DELETE /rbac/roles/:id", () => {
    // --- Permission Gate ---
    it("should return 401 if not logged in", async () => {
      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            "content-type": "application/json",
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 403 if user has no RBAC_management delete permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      // No permissions assigned

      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management read permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "read" }, // Wrong action
      ]);

      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management create permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "create" },
      ]);

      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    it("should return 403 if user only has RBAC_management update permission", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "update" },
      ]);

      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
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
        { featureName: "user_management", action: "delete" }, // Wrong feature
      ]);

      const role = await prisma.role.create({
        data: { name: "TempRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Successful Deletion ---
    it("should delete role successfully", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "OldRole", description: "Deprecated" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.message).toBe("Role deleted successfully");
    });

    it("should remove role from database", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "TemporaryRole" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify deletion in database
      const dbRole = await prisma.role.findUnique({
        where: { id: role.id },
      });

      expect(dbRole).toBeNull();
    });

    // --- ID Validation ---
    it("should return 404 if role does not exist", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const res = await app.handle(
        new Request("http://localhost/rbac/roles/non-existent-id", {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(404);
    });

    // --- Idempotency ---
    it("should return 404 when deleting already deleted role", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "DoubleDeleteRole" },
      });

      // First delete
      const firstDelete = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(firstDelete.status).toBe(200);

      // Second delete attempt
      const secondDelete = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );
      expect(secondDelete.status).toBe(404);
    });

    // --- Cascade / Foreign Key Constraints ---
    it("should delete role and cascade delete its permissions", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "RoleWithPerms" },
      });

      // Create a permission for this role
      const feature = await prisma.feature.create({
        data: { name: "SomeFeature" },
      });

      await prisma.roleFeature.create({
        data: {
          roleId: role.id,
          featureId: feature.id,
          canRead: true,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(200);

      // Verify role is deleted
      const dbRole = await prisma.role.findUnique({ where: { id: role.id } });
      expect(dbRole).toBeNull();

      // Verify permissions are gone (assuming cascade delete is set in schema)
      const permissions = await prisma.roleFeature.findMany({
        where: { roleId: role.id },
      });
      expect(permissions).toHaveLength(0);
    });

    it("should prevent deletion if role is currently assigned to users", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const roleToCheck = await prisma.role.create({
        data: { name: "ActiveManager" },
      });

      // Assign a user to this role
      await prisma.user.create({
        data: {
          email: "active_user@test.com",
          password: "hashedpassword",
          name: "Active User",
          roleId: roleToCheck.id,
        },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${roleToCheck.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      // Expect 400 (Foreign Key Constraint P2003 mapped to 400 in global handler)
      // Or 409 depending on your implementation preference
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.message).toContain("Invalid Reference"); // Or "Cannot delete role in use"

      // Verify role still exists
      const dbRole = await prisma.role.findUnique({
        where: { id: roleToCheck.id },
      });
      expect(dbRole).not.toBeNull();
    });

    // --- Protected System Role ---
    it("should prevent deletion if role is a protected system role", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      // Ensure we have a protected role (e.g. SuperAdmin)
      const systemRole = await prisma.role.upsert({
        where: { name: "SuperAdmin" },
        update: {},
        create: { name: "SuperAdmin", description: "Root" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${systemRole.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
      const body = await res.json();
      // Verify specific error message
      // (You need to implement this check in RbacService.deleteRole)
      expect(body.message).toMatch(/protected/i);
    });

    // --- Response Validation ---
    it("should return deleted role data in response", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "DeletedRole", description: "Gone" },
      });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      const body = await res.json();
      expect(res.status).toBe(200);
      expect(body.data).toBeDefined();
      expect(body.data.id).toBe(role.id);
      expect(body.data.name).toBe("DeletedRole");
    });

    // --- Token Validation ---
    it("should return 401 if access token is expired", async () => {
      const { user } = await createAuthenticatedUser();

      const expiredToken = jwt.sign(
        { userId: user.id, tokenVersion: 0 },
        process.env.JWT_ACCESS_SECRET!,
        { expiresIn: "-1h" },
      );

      const role = await prisma.role.create({ data: { name: "Temp" } });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${expiredToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    it("should return 401 if access token is tampered", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      const token = authHeaders.Authorization.split(" ")[1];
      const tamperedToken = token.slice(0, -5) + "fake";

      const role = await prisma.role.create({ data: { name: "Temp" } });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${tamperedToken}`,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(401);
    });

    // --- Account State ---
    it("should return 403 if user account is disabled", async () => {
      const { authHeaders, user } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      await prisma.user.update({
        where: { id: user.id },
        data: { isActive: false },
      });

      const role = await prisma.role.create({ data: { name: "Temp" } });

      const res = await app.handle(
        new Request(`http://localhost/rbac/roles/${role.id}`, {
          method: "DELETE",
          headers: {
            ...authHeaders,
            "x-forwarded-for": randomIp(),
          },
        }),
      );

      expect(res.status).toBe(403);
    });

    // --- Concurrent Deletion ---
    it("should handle concurrent deletion attempts safely", async () => {
      const { authHeaders } = await createAuthenticatedUser();
      await createTestRoleWithPermissions("TestUser", [
        { featureName: "RBAC_management", action: "delete" },
      ]);

      const role = await prisma.role.create({
        data: { name: "RaceConditionRole" },
      });

      const [first, second, third] = await Promise.all([
        app.handle(
          new Request(`http://localhost/rbac/roles/${role.id}`, {
            method: "DELETE",
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
        app.handle(
          new Request(`http://localhost/rbac/roles/${role.id}`, {
            method: "DELETE",
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
        app.handle(
          new Request(`http://localhost/rbac/roles/${role.id}`, {
            method: "DELETE",
            headers: { ...authHeaders, "x-forwarded-for": randomIp() },
          }),
        ),
      ]);

      const statuses = [first.status, second.status, third.status].sort();

      // One should succeed (200), others should fail (404)
      const successCount = statuses.filter((s) => s === 200).length;
      const notFoundCount = statuses.filter((s) => s === 404).length;

      expect(successCount).toBe(1);
      expect(notFoundCount).toBe(2);
    });
  });
});
