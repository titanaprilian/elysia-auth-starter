export class DeleteSelfError extends Error {
  constructor(message = "You cannot delete your own account.") {
    super(message);
  }
}

export class CreateSystemError extends Error {
  constructor(
    message: string = "Can't create another user with role SuperAdmin",
  ) {
    super(message);
  }
}

export class UpdateSystemError extends Error {
  constructor(
    message: string = "Can't update status user with role SuperAdmin",
  ) {
    super(message);
  }
}
