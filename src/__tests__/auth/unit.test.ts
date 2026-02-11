import { describe, it, expect, mock, spyOn, beforeEach } from "bun:test";
import { prisma } from "../__mocks__/prisma";

mock.module("@/libs/prisma", () => {
  return { prisma };
});

import { AuthService } from "@/modules/auth/service";
import {
  AccountDisabledError,
  TokenMismatchError,
  UnauthorizedError,
} from "@/modules/auth/error";

// Define a reusable mock user
const MOCK_USER = {
  id: "user_123",
  email: "test@example.com",
  name: "Test User",
  password: "hashed_password_string",
  isActive: true,
  tokenVersion: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
};

// Helper to create a standard stored token mock
const createStoredToken = (overrides = {}) => ({
  id: "token_id_1",
  token: "valid_refresh_token_123",
  userId: MOCK_USER.id,
  revoked: false,
  expiresAt: new Date(Date.now() + 100000),
  createdAt: new Date(),
  updatedAt: new Date(),
  user: MOCK_USER,
  ...overrides,
});

describe("AuthService", () => {
  beforeEach(() => {
    mock.restore();
    prisma.user.findUnique.mockReset();
    prisma.user.update.mockReset();
    prisma.refreshToken.findUnique.mockReset();
    prisma.refreshToken.update.mockReset();
    prisma.refreshToken.updateMany.mockReset();
    prisma.refreshToken.create.mockReset();
  });

  describe("login", () => {
    it("should login successfully with correct credentials", async () => {
      prisma.user.findUnique.mockResolvedValue(MOCK_USER);
      spyOn(Bun.password, "verify").mockResolvedValue(true);

      const result = await AuthService.login({
        email: "test@example.com",
        password: "password123",
      });

      expect(result).not.toBeNull();
      expect(result?.email).toBe(MOCK_USER.email);
    });

    it("should throw AccountDisabledError if account is disabled", async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...MOCK_USER,
        isActive: false, // 🟢 Disabled
      });

      spyOn(Bun.password, "verify").mockResolvedValue(true);

      expect(
        AuthService.login({
          email: "test@example.com",
          password: "password123",
        }),
      ).rejects.toThrow(AccountDisabledError);
    });
  });

  describe("refresh", () => {
    const VALID_REFRESH_TOKEN = "valid_refresh_token_123";

    it("should throw AccountDisabledError if user is disabled", async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        createStoredToken({
          user: { ...MOCK_USER, isActive: false }, // 🟢 Disabled User
        }),
      );

      expect(
        AuthService.refresh({
          userId: MOCK_USER.id,
          tokenVersion: MOCK_USER.tokenVersion,
          refreshToken: VALID_REFRESH_TOKEN,
        }),
      ).rejects.toThrow(AccountDisabledError);
    });

    it("should throw UnauthorizedError if token version mismatch", async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        createStoredToken({
          user: { ...MOCK_USER, tokenVersion: 5 }, // DB has v5
        }),
      );

      expect(
        AuthService.refresh({
          userId: MOCK_USER.id,
          tokenVersion: 4, // Payload has v4
          refreshToken: VALID_REFRESH_TOKEN,
        }),
      ).rejects.toThrow(UnauthorizedError);
    });
  });

  describe("logoutAll", () => {
    // 🟢 New Requirement: Mock the initiating token
    it("should verify initiating token before revoking all sessions", async () => {
      // Mock the token used to call the endpoint
      prisma.refreshToken.findUnique.mockResolvedValue(createStoredToken());

      // Mock the update transaction
      prisma.$transaction.mockResolvedValue([{ count: 5 }, MOCK_USER]);

      await AuthService.logoutAll(MOCK_USER.id, "token_id_1", 1);

      // Verify Transaction
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: MOCK_USER.id, revoked: false },
        data: { revoked: true },
      });
      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: MOCK_USER.id },
        data: { tokenVersion: { increment: 1 } },
      });
    });

    it("should block logoutAll if initiating token is revoked", async () => {
      // Mock the token as already revoked
      prisma.refreshToken.findUnique.mockResolvedValue(
        createStoredToken({
          revoked: true,
        }),
      );

      expect(
        AuthService.logoutAll(MOCK_USER.id, "token_id_1", 1),
      ).rejects.toThrow(UnauthorizedError);

      // Should NOT have run the nuke
      expect(prisma.refreshToken.updateMany).not.toHaveBeenCalled();
    });

    it("should block logoutAll if user account is disabled", async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        createStoredToken({
          user: { ...MOCK_USER, isActive: false },
        }),
      );

      expect(
        AuthService.logoutAll(MOCK_USER.id, "token_id_1", 1),
      ).rejects.toThrow(AccountDisabledError);
    });

    it("should block logoutAll if token version is stale", async () => {
      prisma.refreshToken.findUnique.mockResolvedValue(
        createStoredToken({
          user: { ...MOCK_USER, tokenVersion: 2 }, // User changed password recently
        }),
      );

      expect(
        AuthService.logoutAll(MOCK_USER.id, "token_id_1", 1), // Using old token (v1)
      ).rejects.toThrow(TokenMismatchError);
    });
  });

  describe("me", () => {
    it("should return user profile if found and versions match", async () => {
      prisma.user.findUnique.mockResolvedValue(MOCK_USER);

      const result = await AuthService.me(MOCK_USER.id, 1); // Version 1 matches Mock

      expect(result).not.toBeNull();
      expect(result?.email).toBe(MOCK_USER.email);
    });

    it("should throw UnauthorizedError if user not found", async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      expect(AuthService.me("non_existent_id", 1)).rejects.toThrow(
        UnauthorizedError,
      );
    });

    it("should throw AccountDisabledError if user is inactive", async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...MOCK_USER,
        isActive: false,
      });

      expect(AuthService.me(MOCK_USER.id, 1)).rejects.toThrow(
        AccountDisabledError,
      );
    });

    it("should throw UnauthorizedError if token version mismatch", async () => {
      prisma.user.findUnique.mockResolvedValue({
        ...MOCK_USER,
        tokenVersion: 2, // DB has v2
      });

      expect(
        AuthService.me(MOCK_USER.id, 1), // Token has v1
      ).rejects.toThrow(UnauthorizedError);
    });
  });
});
