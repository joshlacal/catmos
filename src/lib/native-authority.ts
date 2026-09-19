/** Native session coordinate only; never contains the bearer token. */
let authority: { did: string; authRevision: string } | null = null;
export function recordNativeAuthority(value: unknown): void {
  if (value === null) { authority = null; return; }
  const candidate = value as { did?: unknown; authRevision?: unknown };
  if (typeof candidate?.did !== 'string' || typeof candidate.authRevision !== 'string' || !/^[0-9]+$/.test(candidate.authRevision)) {
    authority = null;
    throw new Error('Native session authority is unavailable');
  }
  authority = { did: candidate.did, authRevision: candidate.authRevision };
}
export function clearNativeAuthority(): void { authority = null; }
/** Call synchronously BEFORE any import/queue await. Retain the returned copy. */
export function captureNativeAuthority(args?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!args || !('ownerDid' in args)) return args;
  if (!authority || args.ownerDid !== authority.did || args.ownerRevision !== authority.authRevision) throw new Error('Native account session changed');
  return { ...args, ownerRevision: authority.authRevision };
}
