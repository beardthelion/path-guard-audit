// Fixture for rules/typescript/p4-extractall-unchecked.yaml.

export function extractAllTo(zip: any, dest: string) {
  // ruleid: path-guard-audit-p4-extractall-unchecked-typescript
  zip.extractAllTo(dest);
}

export function tarExtract(tar: any, dest: string) {
  // ruleid: path-guard-audit-p4-extractall-unchecked-typescript
  tar.x({ file: "a.tgz", cwd: dest });
}

export function decompressAll(input: string, dest: string) {
  // ruleid: path-guard-audit-p4-extractall-unchecked-typescript
  return decompress(input, dest);
}

export function checkedExtract(zip: any, dest: string) {
  // ok: path-guard-audit-p4-extractall-unchecked-typescript
  for (const entry of zip.entries()) {
    const target = path.resolve(dest, entry.path);
    if (!target.startsWith(dest + "/")) {
      throw new Error("unsafe member");
    }
  }
  zip.extractAllTo(dest);
}
