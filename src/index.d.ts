import type { Request, Response, NextFunction } from 'express';

export type RejectCode = 'INVALID_SYNTAX' | 'DISPOSABLE' | 'NO_MX' | 'DISPOSABLE_MX';

export interface CheckOk {
  ok: true;
  /** Trimmed, lowercased address. Send mail here. */
  email: string;
  /** Alias-free form (Gmail dots and +tags removed). Use for uniqueness checks only. */
  canonical: string;
  domain: string;
}
export interface CheckFail {
  ok: false;
  code: RejectCode;
  message: string;
  domain?: string;
}
export type CheckResult = CheckOk | CheckFail;

export interface EmailGuardOptions {
  /** Domains never blocked, e.g. privacy relays you accept. */
  allow?: string[];
  /** Extra domains to block. */
  block?: string[];
  /** Extra mail-server hostname suffixes to block. */
  blockMxSuffixes?: string[];
  /** Do the DNS MX lookup. Default true. */
  checkMx?: boolean;
  /** Default 3000. */
  dnsTimeoutMs?: number;
  /** Accept the address when DNS itself fails. Default true. */
  failOpenOnDnsError?: boolean;
  /** Auto-refresh interval once start() is called. 0 disables. Default 24h. */
  refreshIntervalMs?: number;
  /** Remote list, one domain per line. */
  blocklistUrl?: string;
  /** Where refreshed lists are saved. false keeps them in memory only. Default: OS temp dir. */
  cacheFile?: string | false;
  /** Bundled list path. */
  seedFile?: string;
  resolveMx?: (domain: string) => Promise<Array<{ exchange: string; priority: number }>>;
  logger?: (level: 'info' | 'warn', message: string) => void;
}

export interface EmailGuard {
  check(email: unknown): Promise<CheckResult>;
  isDisposableDomain(domain: string): boolean;
  /** Fetch the latest list now. Resolves with the number of domains. */
  refresh(): Promise<number>;
  /** Refresh now and then every refreshIntervalMs. */
  start(): void;
  stop(): void;
  readonly size: number;
}

export function createEmailGuard(options?: EmailGuardOptions): EmailGuard;

/** Synchronous check against the bundled list only (no DNS, no refresh). */
export function isDisposableEmail(email: string): boolean;

export function canonicalize(email: string): string;

export function rejectDisposableEmail(
  guard: EmailGuard,
  options?: { field?: string; status?: number }
): (req: Request, res: Response, next: NextFunction) => Promise<void>;

export const MESSAGES: Record<RejectCode, string>;

declare module 'express-serve-static-core' {
  interface Request {
    emailCheck?: CheckOk;
  }
}
