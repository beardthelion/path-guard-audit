// Same call site but the lockfile pins adm-zip below the sanitizing
// minimum: the P4 stays deterministic.
import AdmZip from 'adm-zip';

interface Ctx {
  storagePath: string;
}

export function install(context: Ctx, blob: Buffer) {
  new AdmZip(blob).extractAllTo(context.storagePath, true, true);
}
