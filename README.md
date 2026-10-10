# path-guard-audit

Static audit of caller-shaped paths and archive members that reach
filesystem sinks. Answers "is this read / write / list / extract /
send-file path actually confined?", not "does this repo touch the
filesystem?".

Threat model: a tool or service that joins, opens, reads, writes,
deletes, or extracts filesystem paths whose value or archive-member
name the caller can influence, and needs the join-root confinement
chain checked end to end. The tool classifies incomplete guards into a
documented P0-P10 taxonomy; it does not itself exploit anything, and it
never runs or contacts the target.

Everything runs through Semgrep Community Edition. Target code is never
executed, nothing is installed, and the scan makes no network calls.

## Install

```console
$ pipx install git+https://github.com/beardthelion/path-guard-audit.git
```

or from a checkout:

```console
$ uvx --from . path-guard-audit scan /path/to/repo
```

The only runtime dependencies are Python >= 3.11 and `semgrep`
(`>=1.177.0,<1.178`, pinned in the package metadata).

## Usage

```console
$ path-guard-audit scan /path/to/repo
$ path-guard-audit scan /path/to/repo --json
$ path-guard-audit scan /path/to/repo --timeout 120
$ path-guard-audit corpus-validate --corpus corpus
$ path-guard-audit --version
```

Exit codes:

- `0` -- clean, or only manual-review checklist candidates were found
- `1` -- at least one deterministic finding or unrecognized guard
- `2` -- operational failure (missing semgrep, timeout, parse failure
  covering all files, or `analysis_incomplete`)

## What counts as a complete guard

A path operation is complete when all of the following hold:

1. The path is canonicalized (`.`, `..`, separators, symlinks resolved
   by an explicit policy) before it is used.
2. After canonicalization, a boundary check confines the result to a
   fixed root with a correct comparison (`base + sep`, not raw
   `startswith` of the raw string).
3. NUL bytes, alternate data streams, and unexpected schemes (`file:`,
   UNC) are rejected according to the platform policy.
4. For archives, every member name is validated before writing, and
   link entries cannot escape the extraction root.
5. If a TOCTOU window exists between validation and open, the check is
   re-validated at use time. This is a manual checklist item: static
   analysis cannot close it reliably.

Recognized complete helpers (name-matched): `safe_join`,
`is_path_within_directory`, `assert_under_root`,
`resolve_and_check_within_root`, `is_within_directory`, `is_safe_path`,
`safe_path`, `secure_join`, `resolve_within`, `assert_inside`,
`contained_path`, `is_inside_root`, `assert_under_base`,
`check_path_inside`, `guard_path`, `assert_safe_path`,
`ensure_path_inside`, and `file_utils.validate_upload_path`.

Anything else that reads as a guard is reported as
`guard detected, shape unrecognized` for manual review. A helper's
name is a name, not a proof; inspect the implementation before
trusting the classification.

## Taxonomy

| Class | Meaning | Tier |
|-------|---------|------|
| P0 | no guard: caller-shaped path reaches a sink with no guard vocabulary | deterministic |
| P1 | `..` strip/split or basename-style only | deterministic |
| P2 | prefix/suffix check without canonicalization | deterministic |
| P3 | join to base with no boundary check | deterministic |
| P4 | archive member names not validated (Zip Slip) | deterministic |
| P5 | symlink/link escapes | checklist |
| P6 | platform path quirks (alt separators, schemes, ADS, NUL) | deterministic |
| P7 | URL/URI decoded into a filesystem path | deterministic |
| P8 | weak or default-off allowlist (unanchored regex, env bypass, empty default) | deterministic |
| P9 | guard coverage across entry points | checklist |
| P10 | sensitive paths on a caller-influenced base | checklist |

`docs/taxonomy.md` has the full definitions. See
`docs/source-sink-matrix.md` for the source/sink/probe vocabulary.

## How a scan resolves a site

Raw semgrep hits are inputs, not verdicts. For every recognized entry
point (the "site"), the CLI resolves:

1. If a deterministic weak-class finding (P1-P4, P6-P8) fired inside the
   site and its source matches a sink bound to the site, the site is a
   deterministic finding of that class.
2. Otherwise, if a raw P0 fired but the sink's argument matches the
   argument of a recognized complete-guard call in the same site, the
   site is `recognized_complete` and suppressed.
3. Otherwise, if a raw P0 fired and an intervening call or
   check-and-throw that reads as validation exists in the site, the site
   is `guard detected, shape unrecognized`.
4. Otherwise the raw P0 stays a deterministic P0 finding.

Argument-binding means an unrelated `assert_under_root(config_path)` in
the same handler cannot launder `open(path)`: the sink argument must be
the same identifier the guard call touched.

## Clean results

`no_path_surface_detected` means no recognized entry point, filesystem
sink, or checklist candidate was found. It does not mean the repo is
safe; it means there was nothing for this analyzer to look at. The same
honesty applies to `CLEAN` corpus labels: a CLEAN instance is one where
no deterministic class fires under the documented analyzer ceilings, not
one that is provably free of path handling.

## Boundaries

- The analysis is intra-function. A guard in `f` that protects a sink
  in `g` via an argument is visible only if the taint reaches the sink
  inside one function body. Inter-procedural flows fall to
  `guard detected, shape unrecognized`.
- The site resolution binds by source identifier. A guard call that
  does not touch the sink's identifier does not suppress the raw P0.
- String strips alone (P1) and prefix checks without canonicalization
  (P2) are treated as deterministic, not "weak but maybe fine". The
  bypasses are canonical: `....//` after a strip, `base + "evil"` after
  a `startswith`, `..\\` on Windows.
- Archive member checks enumerate Python `zipfile`/`tarfile`/
  `shutil.unpack_archive` and TypeScript `adm-zip`/`tar`/`decompress`/
  `unzipper` shapes.
- Target `.gitignore`, `.semgrepignore`, and inline `# nosemgrep` are
  not honored for exclusions, and they are listed in the coverage
  report. `node_modules`, `dist`, `build`, `vendor(s)`, `third_party`,
  `venv`, and `.venv` are excluded and listed.
- Test and example paths are flagged `(under a test/example path)` in
  the output; they are never dropped.
- The scan runs semgrep with `--metrics off`, `--disable-version-check`,
  `--no-git-ignore`, and `--disable-nosem`. A smoke test asserts no
  `connect()` during a scan (`tests/test_offline_scan.py`, strace-based
  on Linux; run it yourself under `strace -f -e trace=network` to audit).

## Corpus

`corpus/` contains labeled vulnerable and guarded snippets under
`corpus/manifest.jsonl`, with pinned upstream licenses in
`corpus/NOTICE`. `path-guard-audit corpus-validate` scans the corpus
and fails if any deterministic class misses or a guarded anchor trips a
deterministic rule. Run `python scripts/fetch_corpus.py --check` to
verify the vendored files match the manifest pins.
