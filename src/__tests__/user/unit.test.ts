import { describe, it, expect, mock, beforeEach, spyOn } from "bun:test";
import { prisma } from "../__mocks__/prisma";

const TEST_CUID = "ckv9x3y9x0001qz1abcde1234";

mock.module("@/libs/prisma", () => {
  return { prisma };
});

import { UserService } from "@/modules/user/service";

describe("UserService", () => {
  beforeEach(() => {
    mock.restore();
    prisma.user.findMany.mockReset();
    prisma.user.findUnique.mockReset();
    prisma.user.create.mockReset();
    prisma.user.update.mockReset();
    prisma.user.delete.mockReset();
  });

  it("should get users", async () => {
    prisma.user.findMany.mockResolvedValue([]);

    const users = await UserService.getUsers();

    expect(users).toEqual([]);
    expect(prisma.user.findMany).toHaveBeenCalled();
  });

  it("should get user by id", async () => {
    prisma.user.findUnique.mockResolvedValue({
      id: TEST_CUID,
      email: "test@test.com",
      name: "Test User",
    });

    const user = await UserService.getUser(TEST_CUID);

    expect(user).not.toBeNull();
    expect(user?.id).toBe(TEST_CUID);
    expect(user?.email).toBe("test@test.com");
  });

  it("should return null if user not found", async () => {
    prisma.user.findUnique.mockResolvedValue(null);

    const user = await UserService.getUser("non-existent-id");
    expect(user).toBeNull();
  });

  it("should create user with hashed password", async () => {
    const plainPassword = "password123";
    spyOn(Bun.password, "hash").mockResolvedValue("hashed_secret_123");

    prisma.user.create.mockImplementation(async (args) => ({
      id: TEST_CUID,
      email: args.data.email,
      name: null,
      password: args.data.password,
      createdAt: new Date(),
      updatedAt: new Date(),
    }));

    const user = await UserService.createUser({
      email: "test@test.com",
      password: plainPassword,
    });

    expect(user.email).toBe("test@test.com");
    expect(user.password).toBe("hashed_secret_123");
    expect(prisma.user.create).toHaveBeenCalled();
  });

  it("should update user details", async () => {
    prisma.user.update.mockResolvedValue({
      id: TEST_CUID,
      email: "test@test.com",
      name: "Updated",
      password: "old_hash",
    });

    const updated = await UserService.updateUser(TEST_CUID, {
      name: "Updated",
    });

    expect(updated.name).toBe("Updated");
    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: TEST_CUID },
      data: { name: "Updated" },
    });
  });

  it("should hash password when updating password", async () => {
    const newPlainPassword = "newPass123";

    spyOn(Bun.password, "hash").mockResolvedValue("new_hashed_secret");

    prisma.user.update.mockImplementation(async (args) => ({
      id: TEST_CUID,
      email: "test@test.com",
      name: "Test",
      password: args.data.password, // Should be the new hash
    }));

    const updated = await UserService.updateUser(TEST_CUID, {
      password: newPlainPassword,
    });

    expect(updated.password).toBe("new_hashed_secret");
  });

  it("should delete user", async () => {
    prisma.user.delete.mockResolvedValue({
      id: TEST_CUID,
      email: "deleted@test.com",
    });

    const deleted = await UserService.deleteUser(TEST_CUID);
    expect(deleted.id).toBe(TEST_CUID);
    expect(prisma.user.delete).toHaveBeenCalledWith({
      where: { id: TEST_CUID },
    });
  });
});
