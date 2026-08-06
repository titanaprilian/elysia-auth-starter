export class AccountDisabledError extends Error {
  readonly key: string;

  constructor(locale: string = "en") {
    super("Your Account is disabled");
    this.key = "ACCOUNT_DISABLES";
  }
}

export class UnauthorizedError extends Error {
  readonly key: string;

  constructor(locale: string = "en", key: string = "UNAUTHRIZED") {
    super("Unaithorized");
    this.key = key;
  }
}
