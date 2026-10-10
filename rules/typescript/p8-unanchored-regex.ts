// Fixture for rules/typescript/p8-unanchored-regex.yaml.

export function regexTest(path: string) {
  // ruleid: path-guard-audit-p8-unanchored-regex-typescript
  if (/^\/srv/.test(path)) {
    return path;
  }
  return "";
}

export function matchCheck(path: string) {
  // ruleid: path-guard-audit-p8-unanchored-regex-typescript
  return path.match(/\.jpg/);
}
