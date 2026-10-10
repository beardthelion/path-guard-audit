// Fixture for rules/typescript/p4-archive-member.yaml and
// rules/typescript/p4-extractall-unchecked.yaml.

declare const fs: any;

export function memberWrite(zip: any, dest: string) {
  for (const entry of zip.entries()) {
    // ruleid: path-guard-audit-p4-archive-member-typescript
    fs.writeFileSync(entry.path, "x");
  }
}

export function memberExtract(zip: any, member: any, dest: string) {
  // ruleid: path-guard-audit-p4-archive-member-typescript
  zip.extractEntryTo(member, dest);
}

export function guardedMember(zip: any, dest: string) {
  for (const entry of zip.entries()) {
    const name = safeJoin(dest, entry.fileName);
    // ok: path-guard-audit-p4-archive-member-typescript
    fs.writeFileSync(name, "x");
  }
}
