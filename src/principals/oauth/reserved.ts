/** Engine-controlled OAuth token parameters. Extension/extra maps cannot override these. */

export const ENGINE_RESERVED_TOKEN_PARAMS = [
  'grant_type',
  'client_id',
  'client_secret',
  'username',
  'password',
  'code',
  'code_verifier',
  'redirect_uri',
  'refresh_token',
  'assertion',
  'client_assertion',
  'client_assertion_type',
] as const;

export type ReservedTokenParam = (typeof ENGINE_RESERVED_TOKEN_PARAMS)[number];

const ENGINE_SET = new Set<string>(ENGINE_RESERVED_TOKEN_PARAMS);

export function reservedParamSet(adapterReserved: readonly string[] = []): Set<string> {
  return new Set([...ENGINE_SET, ...adapterReserved]);
}

export function collidingReservedKeys(
  maps: Array<Record<string, string> | undefined | null>,
  extraReserved: readonly string[] = [],
): string[] {
  const reserved = reservedParamSet(extraReserved);
  const hits: string[] = [];
  for (const map of maps) {
    if (!map) continue;
    for (const key of Object.keys(map)) {
      if (reserved.has(key) && !hits.includes(key)) hits.push(key);
    }
  }
  return hits;
}
