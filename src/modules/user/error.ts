export class DeleteSelfError extends Error {
  constructor(message = "You cannot delete your own account.") {
    super(message);
  }
}
