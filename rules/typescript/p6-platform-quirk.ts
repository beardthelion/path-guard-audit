// Fixture for rules/typescript/p6-platform-quirk.yaml.

export function splitPosix(path: string) {
  // ruleid: path-guard-audit-p6-platform-quirk-typescript
  if (path.split("/").includes("..")) {
    return null;
  }
  return path;
}

export function fileScheme(path: string) {
  // ruleid: path-guard-audit-p6-platform-quirk-typescript
  return path.replace("file://", "");
}

export function colonSplit(path: string) {
  // ruleid: path-guard-audit-p6-platform-quirk-typescript
  return path.split(":");
}

export function genericCheck(path: string) {
  // ok: path-guard-audit-p6-platform-quirk-typescript
  if (path.includes("..")) {
    return null;
  }
  return path;
}
