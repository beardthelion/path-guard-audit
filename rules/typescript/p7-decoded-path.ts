// Fixture for rules/typescript/p7-decoded-path.yaml.

export function decoded(url: string) {
  // ruleid: path-guard-audit-p7-decoded-path-typescript
  return decodeURIComponent(url);
}

export function urlPath(url: string) {
  // ruleid: path-guard-audit-p7-decoded-path-typescript
  return new URL(url).pathname;
}

export function urlParse(url: string) {
  // ruleid: path-guard-audit-p7-decoded-path-typescript
  return url.parse(url).pathname;
}

export function plain(path: string) {
  // ok: path-guard-audit-p7-decoded-path-typescript
  return path;
}
