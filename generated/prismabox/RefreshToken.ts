import { t } from "elysia";

import { __transformDate__ } from "./__transformDate__";

import { __nullable__ } from "./__nullable__";

export const RefreshTokenPlain = t.Object(
  {
    id: t.String(),
    token: t.String(),
    userId: t.String(),
    expiresAt: t.Date(),
    revoked: t.Boolean(),
    createdAt: t.Date(),
  },
  { additionalProperties: false },
);

export const RefreshTokenRelations = t.Object(
  {
    user: t.Object(
      {
        id: t.String(),
        email: t.String(),
        password: t.String(),
        name: __nullable__(t.String()),
        isActive: t.Boolean(),
        tokenVersion: t.Integer(),
        roleId: t.String(),
        createdAt: t.Date(),
        updatedAt: t.Date(),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);

export const RefreshTokenPlainInputCreate = t.Object(
  { token: t.String(), expiresAt: t.Date(), revoked: t.Optional(t.Boolean()) },
  { additionalProperties: false },
);

export const RefreshTokenPlainInputUpdate = t.Object(
  {
    token: t.Optional(t.String()),
    expiresAt: t.Optional(t.Date()),
    revoked: t.Optional(t.Boolean()),
  },
  { additionalProperties: false },
);

export const RefreshTokenRelationsInputCreate = t.Object(
  {
    user: t.Object(
      {
        connect: t.Object(
          {
            id: t.String({ additionalProperties: false }),
          },
          { additionalProperties: false },
        ),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);

export const RefreshTokenRelationsInputUpdate = t.Partial(
  t.Object(
    {
      user: t.Object(
        {
          connect: t.Object(
            {
              id: t.String({ additionalProperties: false }),
            },
            { additionalProperties: false },
          ),
        },
        { additionalProperties: false },
      ),
    },
    { additionalProperties: false },
  ),
);

export const RefreshTokenWhere = t.Partial(
  t.Recursive(
    (Self) =>
      t.Object(
        {
          AND: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
          NOT: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
          OR: t.Array(Self, { additionalProperties: false }),
          id: t.String(),
          token: t.String(),
          userId: t.String(),
          expiresAt: t.Date(),
          revoked: t.Boolean(),
          createdAt: t.Date(),
        },
        { additionalProperties: false },
      ),
    { $id: "RefreshToken" },
  ),
);

export const RefreshTokenWhereUnique = t.Recursive(
  (Self) =>
    t.Intersect(
      [
        t.Partial(
          t.Object(
            { id: t.String(), token: t.String() },
            { additionalProperties: false },
          ),
          { additionalProperties: false },
        ),
        t.Union(
          [t.Object({ id: t.String() }), t.Object({ token: t.String() })],
          { additionalProperties: false },
        ),
        t.Partial(
          t.Object({
            AND: t.Union([
              Self,
              t.Array(Self, { additionalProperties: false }),
            ]),
            NOT: t.Union([
              Self,
              t.Array(Self, { additionalProperties: false }),
            ]),
            OR: t.Array(Self, { additionalProperties: false }),
          }),
          { additionalProperties: false },
        ),
        t.Partial(
          t.Object(
            {
              id: t.String(),
              token: t.String(),
              userId: t.String(),
              expiresAt: t.Date(),
              revoked: t.Boolean(),
              createdAt: t.Date(),
            },
            { additionalProperties: false },
          ),
        ),
      ],
      { additionalProperties: false },
    ),
  { $id: "RefreshToken" },
);

export const RefreshTokenSelect = t.Partial(
  t.Object(
    {
      id: t.Boolean(),
      token: t.Boolean(),
      userId: t.Boolean(),
      user: t.Boolean(),
      expiresAt: t.Boolean(),
      revoked: t.Boolean(),
      createdAt: t.Boolean(),
      _count: t.Boolean(),
    },
    { additionalProperties: false },
  ),
);

export const RefreshTokenInclude = t.Partial(
  t.Object(
    { user: t.Boolean(), _count: t.Boolean() },
    { additionalProperties: false },
  ),
);

export const RefreshTokenOrderBy = t.Partial(
  t.Object(
    {
      id: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      token: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      userId: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      expiresAt: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      revoked: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      createdAt: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
    },
    { additionalProperties: false },
  ),
);

export const RefreshToken = t.Composite(
  [RefreshTokenPlain, RefreshTokenRelations],
  { additionalProperties: false },
);

export const RefreshTokenInputCreate = t.Composite(
  [RefreshTokenPlainInputCreate, RefreshTokenRelationsInputCreate],
  { additionalProperties: false },
);

export const RefreshTokenInputUpdate = t.Composite(
  [RefreshTokenPlainInputUpdate, RefreshTokenRelationsInputUpdate],
  { additionalProperties: false },
);
