import { t } from "elysia";

import { __transformDate__ } from "./__transformDate__";

import { __nullable__ } from "./__nullable__";

export const RoleFeaturePlain = t.Object(
  {
    id: t.String(),
    roleId: t.String(),
    featureId: t.String(),
    canCreate: t.Boolean(),
    canRead: t.Boolean(),
    canUpdate: t.Boolean(),
    canDelete: t.Boolean(),
    canPrint: t.Boolean(),
  },
  { additionalProperties: false },
);

export const RoleFeatureRelations = t.Object(
  {
    role: t.Object(
      {
        id: t.String(),
        name: t.String(),
        description: __nullable__(t.String()),
        createdAt: t.Date(),
        updatedAt: t.Date(),
      },
      { additionalProperties: false },
    ),
    feature: t.Object(
      {
        id: t.String(),
        name: t.String(),
        description: __nullable__(t.String()),
        createdAt: t.Date(),
        updatedAt: t.Date(),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);

export const RoleFeaturePlainInputCreate = t.Object(
  {
    canCreate: t.Optional(t.Boolean()),
    canRead: t.Optional(t.Boolean()),
    canUpdate: t.Optional(t.Boolean()),
    canDelete: t.Optional(t.Boolean()),
    canPrint: t.Optional(t.Boolean()),
  },
  { additionalProperties: false },
);

export const RoleFeaturePlainInputUpdate = t.Object(
  {
    canCreate: t.Optional(t.Boolean()),
    canRead: t.Optional(t.Boolean()),
    canUpdate: t.Optional(t.Boolean()),
    canDelete: t.Optional(t.Boolean()),
    canPrint: t.Optional(t.Boolean()),
  },
  { additionalProperties: false },
);

export const RoleFeatureRelationsInputCreate = t.Object(
  {
    role: t.Object(
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
    feature: t.Object(
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

export const RoleFeatureRelationsInputUpdate = t.Partial(
  t.Object(
    {
      role: t.Object(
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
      feature: t.Object(
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

export const RoleFeatureWhere = t.Partial(
  t.Recursive(
    (Self) =>
      t.Object(
        {
          AND: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
          NOT: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
          OR: t.Array(Self, { additionalProperties: false }),
          id: t.String(),
          roleId: t.String(),
          featureId: t.String(),
          canCreate: t.Boolean(),
          canRead: t.Boolean(),
          canUpdate: t.Boolean(),
          canDelete: t.Boolean(),
          canPrint: t.Boolean(),
        },
        { additionalProperties: false },
      ),
    { $id: "RoleFeature" },
  ),
);

export const RoleFeatureWhereUnique = t.Recursive(
  (Self) =>
    t.Intersect(
      [
        t.Partial(
          t.Object(
            {
              id: t.String(),
              roleId_featureId: t.Object(
                { roleId: t.String(), featureId: t.String() },
                { additionalProperties: false },
              ),
            },
            { additionalProperties: false },
          ),
          { additionalProperties: false },
        ),
        t.Union(
          [
            t.Object({ id: t.String() }),
            t.Object({
              roleId_featureId: t.Object(
                { roleId: t.String(), featureId: t.String() },
                { additionalProperties: false },
              ),
            }),
          ],
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
              roleId: t.String(),
              featureId: t.String(),
              canCreate: t.Boolean(),
              canRead: t.Boolean(),
              canUpdate: t.Boolean(),
              canDelete: t.Boolean(),
              canPrint: t.Boolean(),
            },
            { additionalProperties: false },
          ),
        ),
      ],
      { additionalProperties: false },
    ),
  { $id: "RoleFeature" },
);

export const RoleFeatureSelect = t.Partial(
  t.Object(
    {
      id: t.Boolean(),
      roleId: t.Boolean(),
      role: t.Boolean(),
      featureId: t.Boolean(),
      feature: t.Boolean(),
      canCreate: t.Boolean(),
      canRead: t.Boolean(),
      canUpdate: t.Boolean(),
      canDelete: t.Boolean(),
      canPrint: t.Boolean(),
      _count: t.Boolean(),
    },
    { additionalProperties: false },
  ),
);

export const RoleFeatureInclude = t.Partial(
  t.Object(
    { role: t.Boolean(), feature: t.Boolean(), _count: t.Boolean() },
    { additionalProperties: false },
  ),
);

export const RoleFeatureOrderBy = t.Partial(
  t.Object(
    {
      id: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      roleId: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      featureId: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      canCreate: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      canRead: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      canUpdate: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      canDelete: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
      canPrint: t.Union([t.Literal("asc"), t.Literal("desc")], {
        additionalProperties: false,
      }),
    },
    { additionalProperties: false },
  ),
);

export const RoleFeature = t.Composite(
  [RoleFeaturePlain, RoleFeatureRelations],
  { additionalProperties: false },
);

export const RoleFeatureInputCreate = t.Composite(
  [RoleFeaturePlainInputCreate, RoleFeatureRelationsInputCreate],
  { additionalProperties: false },
);

export const RoleFeatureInputUpdate = t.Composite(
  [RoleFeaturePlainInputUpdate, RoleFeatureRelationsInputUpdate],
  { additionalProperties: false },
);
