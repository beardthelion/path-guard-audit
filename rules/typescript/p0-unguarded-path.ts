// Fixture for rules/typescript/p0-unguarded-path.yaml.
import * as fs from "fs";

declare const app: any;
declare const server: any;

export function readTool(path: string) {
  // ruleid: path-guard-audit-p0-typescript
  return fs.readFileSync(path, "utf8");
}

export function writeUpload(filename: string, data: string) {
  // ruleid: path-guard-audit-p0-typescript
  fs.writeFileSync(filename, data);
}

export async function streamFile(filepath: string) {
  // ruleid: path-guard-audit-p0-typescript
  return fs.createReadStream(filepath);
}

app.get("/file", (req: any, res: any) => {
  // ruleid: path-guard-audit-p0-typescript
  return res.sendFile(req.query.path);
});

server.tool("read_file", async (args: any) => {
  // ruleid: path-guard-audit-p0-typescript
  return fs.readFileSync(args.path, "utf8");
});

server.registerTool("write_file", async ({ path }: any) => {
  // ruleid: path-guard-audit-p0-typescript
  return fs.writeFileSync(path, "x");
});

export function viaMember(zf: any, dest: string) {
  for (const entry of zf.entries()) {
    // ruleid: path-guard-audit-p0-typescript
    fs.writeFileSync(entry.name, "x");
  }
}

export function completeGuard(base: string, name: string) {
  const checked = safeJoin(base, name);
  // ok: path-guard-audit-p0-typescript
  return fs.readFileSync(checked, "utf8");
}

export function literalPath() {
  // ok: path-guard-audit-p0-typescript
  return fs.readFileSync("/etc/motd", "utf8");
}
