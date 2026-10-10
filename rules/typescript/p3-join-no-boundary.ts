// Fixture for rules/typescript/p3-join-no-boundary.yaml.

export function joinThenRead(base: string, name: string) {
  // ruleid: path-guard-audit-p3-join-no-boundary-typescript
  const joined = path.join(base, name);
  return joined;
}

export function resolveThenRead(base: string, name: string) {
  // ruleid: path-guard-audit-p3-join-no-boundary-typescript
  return path.resolve(base, name);
}

export function templateJoin(dir: string, name: string) {
  // ruleid: path-guard-audit-p3-join-no-boundary-typescript
  return `${dir}/${name}`;
}

export function joinWithBoundary(base: string, name: string) {
  const joined = path.join(base, name);
  // ok: path-guard-audit-p3-join-no-boundary-typescript
  if (!joined.startsWith(base)) {
    return "";
  }
  return joined;
}
