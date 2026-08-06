export class DeleteSelfError extends Error {
  readonly key: string;

  constructor(locale: string = "en") {
    super("Can't delete your own account");
    this.key = "SELF_DELETE";
  }
}

export class CreateSystemError extends Error {
  readonly key: string;

  constructor() {
    super("Can't add another system admin");
    this.key = "CREATE_SYSTEM_ERROR";
  }
}

export class UpdateSystemError extends Error {
  readonly key: string;

  constructor() {
    super("Can't update system admin");
    this.key = "UPDATE_SYSTEM_ERROR";
  }
}
