// Fixture for rules/typescript/p2-prefix-no-resolve.yaml.

export function prefixCheck(path: string) {
  // ruleid: path-guard-audit-p2-prefix-no-resolve-typescript
  if (path.startsWith("/srv/files")) {
    return path;
  }
  return "";
}

export function suffixCheck(filename: string) {
  // ruleid: path-guard-audit-p2-prefix-no-resolve-typescript
  if (filename.endsWith(".jpg")) {
    return filename;
  }
  return "";
}

export function resolvedPrefix(base: string, name: string) {
  const full = path.resolve(base, name);
  // ok: path-guard-audit-p2-prefix-no-resolve-typescript
  if (full.startsWith(base + "/")) {
    return full;
  }
  return "";
}
