// adm-zip >= 0.6.1 sanitizes member names inside extractAllTo; the
// lockfile below pins it. The P4 sink demotes to a dependency-guard
// note (manual review), never recognized_complete.
import AdmZip from 'adm-zip';

interface Ctx {
  storagePath: string;
}

export function install(context: Ctx, blob: Buffer) {
  new AdmZip(blob).extractAllTo(context.storagePath, true, true);
}
