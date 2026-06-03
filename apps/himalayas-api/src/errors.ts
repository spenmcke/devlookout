export class DateFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DateFormatError";
  }
}

export class RetryScheduleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RetryScheduleError";
  }
}

export class PoolTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PoolTimeoutError";
  }
}

export class DkimVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DkimVerificationError";
  }
}
