export type SecretValues = Record<string, string>;

export interface LockGateClientOptions {
  url: string;
  token: string;
  pollInterval?: number;
  requestTimeout?: number;
}

export interface GetConfigOptions {
  signal?: AbortSignal;
}

export class LockGateError extends Error {
  readonly code: string;
  constructor(message: string, code?: string);
}

export class LockGateClient {
  constructor(options: LockGateClientOptions);
  getConfig(options?: GetConfigOptions): Promise<SecretValues>;
}
