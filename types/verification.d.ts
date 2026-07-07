export interface VerificationResult {
  success: boolean;
  error?: string | null;
  timestamp: number;
  [key: string]: unknown;
}

export interface DataEntryVerificationOptions<TEntry = unknown> {
  matchFn?: (entryInDatabase: unknown, expectedEntry: TEntry) => boolean;
  checkLog?: boolean;
}

export function verifyDatabaseUpdate(
  database: unknown,
  identityHash: string,
  expectedWebAuthnDID: string
): Promise<VerificationResult>;

export function verifyIdentityStorage(
  identities: unknown,
  identity: { id: string; hash: string; [key: string]: unknown },
  timeoutMs?: number
): Promise<VerificationResult>;

export function verifyDataEntries<TEntry extends { id: string }>(
  database: unknown,
  dataEntries: TEntry[],
  expectedWebAuthnDID: string,
  options?: DataEntryVerificationOptions<TEntry>
): Promise<Map<string, VerificationResult>>;

export function isValidWebAuthnDID(did: string): boolean;

export function extractWebAuthnDIDSuffix(did: string): string | null;

export function compareWebAuthnDIDs(did1: string, did2: string): boolean;

export function createVerificationResult(
  success: boolean,
  details?: Record<string, unknown>
): VerificationResult;
