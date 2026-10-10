# Changelog

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
