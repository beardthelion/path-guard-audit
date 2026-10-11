# Changelog

## Unreleased

Precision fixes for two false-positive classes found while triaging
real-world smoke hits:

- Canonical-boundary guard recognition. A new site probe
  (`canonical_boundary_guard`) recognizes the in-function pair of a
  canonicalizing assignment (`os.path.realpath`/`abspath`/`normpath`,
  `<expr>.resolve()`; TypeScript `path.resolve`, `fs.realpathSync`,
  `path.normalize`) and a reject-arm `if` that boundary-checks the same
  variable (`v.startswith(root + os.sep)`-with-separator,
  `v.is_relative_to(root)`; `v.startsWith(root + path.sep)`). Resolution
  requires the checked variable to reach a sink's first argument or
  carry the sink as a method receiver, and
  only join/member classes (P2, P3, P4) clear; other classes stay
  deterministic. Near-misses still reported: `startswith(root)` without
  a separator join, checks on un-canonicalized values, conditions with
  no reject arm, and checks on a variable the sink does not consume.
  Fixes the crewAI `remote_template._extract_zip` P4 false positive; the
  site now resolves recognized-complete.
- Dependency-guarded extractors. `adm-zip` `extractAllTo`,
  `extractAllToAsync`, `extractEntryTo`, `extractEntryToAsync` P4
  findings demote to a `dependency-guarded` note (site resolves
  `unrecognized_guard`, never silent) when the file references the
  package, because adm-zip >= 0.6.1 sanitizes member names and rejects
  writes through in-root symlinks. The same mechanism covers
  `extract-zip`'s `extractZip`/`extractZipAsync` (>= 2.0.1, out-of-root
  realpath check per entry), node-tar `tar.x`/`tar.extract`/
  `tar.extractSync` on a tar-ish receiver (>= 6.1.2, default member-name
  confinement plus the 2021 path-safety fixes), and stdlib `zipfile`
  `extractall`/`extract` on a conventional zip handle in a `.py` file
  (`_extract_member` strips `..`/absolute components by design, so no
  version evidence is required). `tarfile.extractall` and
  `shutil.unpack_archive` are deliberately not covered: tar member names
  are unfiltered.
  `package-lock.json`/`package.json`
  exact pins are consulted as offline version evidence: >= the minimum
  records `confirmed`, below the minimum keeps the deterministic P4,
  and no evidence leaves `unverified` with reason
  "dependency-guarded, verify version". Fixes the coc-rust-analyzer
  `downloadServer` P4 false positive; the corpus row keeps its
  vulnerable call-site shape pin with an `accepted_misses` note.

- `--process-timeout` flag on `scan` and `corpus-validate`: raises the
  wall-clock bound on the semgrep subprocess (default 1800s), needed
  for scans of large monorepos.
- Corpus: `dbgpt-flow-import-zip-filename` (CVE-2025-6772 shape,
  raw `os.path.join(temp_dir, file.filename)` upload write) and
  `metagpt-editor-paths` (CVE-2026-19059 shape, `@register_tool` file
  editor with no path confinement) vendored as deterministic anchors.

## 0.1.0 (2026-10-10)

Initial release.

- Python CLI (`path-guard-audit scan`, `corpus-validate`) auditing incomplete
  filesystem and archive path guards in Python and TypeScript codebases.
- P0-P10 taxonomy: P0 no guard recognized, P1 textual dot-dot strip /
  filename sanitization without confinement, P2 prefix/join checks without
  canonicalization, P3 path joining without a correct root boundary, P4
  archive member/extraction path issues (incl. zip slip), P5 archive
  symlink/link manual review, P6 platform quirks (ADS, NUL, UNC, schemes),
  P7 decoded/transformed path bypasses, P8 unanchored regex allowlists and
  env-flag escape hatches, P9 validation/extraction review candidates,
  P10 sensitive-file and credential-path candidates.
- Layered site resolution: deterministic findings, recognized-complete
  guards, unrecognized guards, sinks outside recognized entries,
  parse-failure accounting, deduplicated checklist candidates.
- Human-readable report and stable JSON output
  (`path-guard-audit/v1` schema, `p0-p10/v1` taxonomy).
- Labeled corpus: 17 samples across 13 instances, vendored at pinned SHAs
  from MIT and Apache-2.0 upstreams (crewAI, SuperAGI, Salt,
  coc-rust-analyzer, ThinkRAG, Flare, RDFConverter, modern-tar,
  MCP filesystem server, gptme); corpus-validate is the CI gate.
- Scans are static only: no target code execution, no target dependency
  installation, no network access.
