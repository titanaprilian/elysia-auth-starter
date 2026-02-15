export class DeleteSystemError extends Error {
  constructor(message: string = "Can't delete system role or feature") {
    super(message);
  }
}

export class InvalidFeatureIdError extends Error {
  constructor(message: string = "Invalid feature ID(s)") {
    super(message);
  }
}
