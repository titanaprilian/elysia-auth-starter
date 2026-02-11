export class DeleteSystemError extends Error {
  constructor(message: string = "Can't delete system role or feature") {
    super(message);
  }
}
