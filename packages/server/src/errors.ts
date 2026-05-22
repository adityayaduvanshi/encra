export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message)
    this.name = 'HttpError'
    Object.setPrototypeOf(this, HttpError.prototype)
  }
}

export class NotFoundError extends HttpError {
  constructor(message: string) {
    super(404, message)
    this.name = 'NotFoundError'
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = 'Missing or invalid Authorization header.') {
    super(401, message)
    this.name = 'UnauthorizedError'
  }
}

export class BadRequestError extends HttpError {
  constructor(message: string) {
    super(400, message)
    this.name = 'BadRequestError'
  }
}
