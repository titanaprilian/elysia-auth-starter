import { mock } from "bun:test";

export const prisma = {
  $transaction: mock(),
  user: {
    findMany: mock(),
    findUnique: mock(),
    create: mock(),
    update: mock(),
    delete: mock(),
  },
  refreshToken: {
    findUnique: mock(),
    create: mock(),
    update: mock(),
    updateMany: mock(),
  },
  feature: {
    findMany: mock(),
    create: mock(),
    update: mock(),
    delete: mock(),
  },
  role: {
    findMany: mock(),
    create: mock(),
    update: mock(),
    delete: mock(),
    findUniqueOrThrow: mock(),
  },
  roleFeature: {
    createMany: mock(),
    deleteMany: mock(),
  },
};
