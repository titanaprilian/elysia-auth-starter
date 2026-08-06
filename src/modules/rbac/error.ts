export class ForeignKeyError extends Error {
  readonly key: string;
  readonly field: string;

  constructor(field: string = "unknown") {
    super("Invalid Reference");
    this.key = "INVALID_REFERENCE";
    this.field = field;
  }
}

export class UniqueConstraintError extends Error {
  readonly key: string;
  readonly field: string;

  constructor(target: string = "field") {
    super("Duplicate Error");
    this.key = "DUPLICATE_ERROR";
    this.field = target;
  }
}

export class RecordNotFoundError extends Error {
  readonly key: string;

  constructor() {
    super("Not Found");
    this.key = "NOT_FOUND";
  }
}

export class DeleteSystemError extends Error {
  readonly key: string;

  constructor() {
    super("Can't Delete System Role");
    this.key = "DELETE_SYSTEM_ROLE";
  }
}

export class UpdateSystemError extends Error {
  readonly key: string;

  constructor() {
    super("Can't Update System Role");
    this.key = "UPDATE_SYSTEM_ROLE";
  }
}

export class InvalidFeatureIdError extends Error {
  readonly key: string;

  constructor() {
    super("Invalid Feature ID");
    this.key = "INVALID_FEATURE_ID";
  }
}
