// Fixture for rules/typescript/p0-unguarded-path.yaml (JS target).
const fs = require("fs");

function readTool(path) {
  // ruleid: path-guard-audit-p0-typescript
  return fs.readFileSync(path, "utf8");
}

function literalPath() {
  // ok: path-guard-audit-p0-typescript
  return fs.readFileSync("/etc/motd", "utf8");
}
