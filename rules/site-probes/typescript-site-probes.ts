// Fixture for rules/site-probes/typescript-site-probes.yaml.

declare const app: any;
declare const server: any;
declare const fs: any;

// ruleid: path-guard-audit-probe-handler-source-typescript
app.get("/file", (req: any, res: any) => {
  // ruleid: path-guard-audit-probe-path-sink-typescript
  return res.sendFile(req.query.path);
});

// ruleid: path-guard-audit-probe-handler-source-typescript
export function readTool(path: string) {
  // ruleid: path-guard-audit-probe-path-sink-typescript
  return fs.readFileSync(path);
}

// ruleid: path-guard-audit-probe-handler-source-typescript
export function completeGuard(base: string, name: string) {
  // ruleid: path-guard-audit-probe-complete-guard-typescript
  const checked = safeJoin(base, name);
  // ruleid: path-guard-audit-probe-path-sink-typescript
  return fs.readFileSync(checked);
}

// ruleid: path-guard-audit-probe-handler-source-typescript
export function intervening(path: string) {
  // ruleid: path-guard-audit-probe-intervening-validation-typescript
  validatePath(path);
  // ruleid: path-guard-audit-probe-path-sink-typescript
  return fs.readFileSync(path);
}

// ruleid: path-guard-audit-probe-handler-source-typescript
export function checkThrow(path: string) {
  // ruleid: path-guard-audit-probe-intervening-validation-typescript
  if (!path) {
    throw new Error("empty");
  }
  // ruleid: path-guard-audit-probe-path-sink-typescript
  return fs.readFileSync(path);
}

export function noSurface(x: number) {
  // ok: path-guard-audit-probe-handler-source-typescript
  // ok: path-guard-audit-probe-path-sink-typescript
  // ok: path-guard-audit-probe-complete-guard-typescript
  // ok: path-guard-audit-probe-intervening-validation-typescript
  return x * 2;
}
