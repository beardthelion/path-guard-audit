// Fixture for rules/typescript/p1-dotdot-strip.yaml.

export function stripDotdot(name: string) {
  // ruleid: path-guard-audit-p1-dotdot-strip-typescript
  const cleaned = name.replace(/\.\./g, "");
  return cleaned;
}

export function stripSlashes(filename: string) {
  // ruleid: path-guard-audit-p1-dotdot-strip-typescript
  return filename.replaceAll("/", "_");
}

export function splitDots(name: string) {
  // ruleid: path-guard-audit-p1-dotdot-strip-typescript
  return name.split("..");
}

export function basenameOnly(filepath: string) {
  // ruleid: path-guard-audit-p1-dotdot-strip-typescript
  return path.basename(filepath);
}

export function sanitizeOnly(filename: string) {
  // ruleid: path-guard-audit-p1-dotdot-strip-typescript
  return sanitizeFilename(filename);
}

export function stripThenResolve(base: string, name: string) {
  const cleaned = name.replace(/\.\./g, "");
  const full = path.resolve(base, cleaned);
  // ok: path-guard-audit-p1-dotdot-strip-typescript
  return full;
}
