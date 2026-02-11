export class AccountDisabledError extends Error {
  constructor(message: string = "Account disabled") {
    super(message);
  }
}

export class UnauthorizedError extends Error {
  constructor(message: string = "Unauthorized") {
    super(message);
  }
}
