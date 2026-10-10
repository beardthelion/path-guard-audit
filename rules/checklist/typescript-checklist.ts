// Fixture for rules/checklist/typescript-checklist.yaml.

declare const app: any;
declare const server: any;
declare const fs: any;

// ruleid: path-guard-audit-checklist-p9-typescript
app.post("/upload", (req: any, res: any) => {
  const dest = req.body.dest;
  // ruleid: path-guard-audit-checklist-p5-typescript
  fs.symlink("/x", dest);
  res.send("ok");
});

// ruleid: path-guard-audit-checklist-p9-typescript
server.tool("read_key", async (args: any) => {
  // ruleid: path-guard-audit-checklist-p10-typescript
  return fs.readFile("/home/app/.aws/credentials");
});

export function linkCheck(member: any) {
  // ruleid: path-guard-audit-checklist-p5-typescript
  if (member.linkname) {
    return "x";
  }
  return null;
}

export function noSurface(x: number) {
  // ok: path-guard-audit-checklist-p5-typescript
  // ok: path-guard-audit-checklist-p9-typescript
  // ok: path-guard-audit-checklist-p10-typescript
  return x * 2;
}
