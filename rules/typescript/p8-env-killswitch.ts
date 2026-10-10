// Fixture for rules/typescript/p8-env-killswitch.yaml.

// ruleid: path-guard-audit-p8-typescript-env-killswitch
const bypass = process.env.ALLOW_ANY_PATH;

// ok: path-guard-audit-p8-typescript-env-killswitch
const telemetry = process.env.DISABLE_TELEMETRY;

// ruleid: path-guard-audit-p8-typescript-env-killswitch
const UNSAFE_PATH_ENV = "ALLOW_UNSAFE_PATHS";

// ruleid: path-guard-audit-p8-typescript-env-killswitch
const key = process.env["DISABLE_PATH_CHECKS"];

// ruleid: path-guard-audit-p8-typescript-default-off
const allowedPaths: string[] = [];

// ruleid: path-guard-audit-p8-typescript-default-off
const permittedRoots = null;

// ok: path-guard-audit-p8-typescript-default-off
const maxUploadBytes = 1024;

// ok: path-guard-audit-p8-typescript-default-off
const allowedPaths2 = ["/srv/files"];
