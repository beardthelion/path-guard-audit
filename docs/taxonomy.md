# P0-P10 path-guard completeness taxonomy

This document defines the class set `path-guard-audit` reports. A finding is
always a *site*: a filesystem or archive sink inside one entry-point extent,
resolved against the classes below in precedence order. The taxonomy version
reported in JSON output is `p0-p10/v1`.

## What "complete" means

For every class, a complete guard is the same five-part pipeline:

1. **Normalize / canonicalize the path.** Resolve `.` and `..` segments
   (`os.path.realpath`, `Path.resolve`, `path.resolve`), with an explicit
   symlink policy.
2. **Enforce a root/base allowlist after canonicalization.** A prefix check
   on the resolved path with a correct boundary (`base + os.sep` or an
   equivalent structural check such as `Path.is_relative_to`), never a raw
   `startswith` on the un-resolved string.
3. **Reject hostile path bytes per platform policy.** NUL, alternate data
   streams, unexpected schemes (`file:`), and UNC paths on the platform the
   code runs on.
4. **For archives, validate every member name the same way** before any
   write, and never follow links out of the extract root unless explicitly
   intended.
5. **Re-check at use time** when a TOCTOU window exists between check and
   open. When a static shape cannot prove re-checking, this is a checklist
   item, not a deterministic finding.

Anything less is incomplete. The deterministic rules (P0-P4, P6-P8) name
recognizable incomplete shapes. P5, P9, and P10 are manual-review checklist
classes: they cannot be decided intra-function, so they emit candidates, not
findings.

## P0: no guard

A caller-shaped path or archive-member input reaches a filesystem sink
(`open`, `os.remove`, `shutil.copy`, `Path.write_*`, `send_file`,
`fs.readFile`, `res.sendFile`, an extract call) with no recognized
complete-guard call on the intra-function taint path. Unrecognized or weak
guards do not suppress P0: they keep the raw finding, which site resolution
relabels as a weaker class or as `unrecognized_guard` when evidence exists.

## P1: `..` strip/split only

The guard removes traversal text and stops: `.replace("..", "")`,
`re.sub`/`re.subn` of `..` or `/`, `split("..")`/`split("/")` rebuilding,
`secure_filename` alone, `os.path.basename`. These never canonicalize, so
encoded variants, absolute paths, and platform separators the strip missed
still reach the sink.

## P2: prefix/suffix check without canonicalization

The guard compares the un-resolved path against a root string:
`path.startswith(base)`, `os.path.commonprefix`, a `commonpath` call with no
`realpath`/`resolve` in the same function, or `in`-membership on a path list.
`base + "evil"` (`/srv/files_evil`) passes a `startswith` check; `..` passes
because nothing canonicalized it.

## P3: join to base without resolve + boundary check

`os.path.join(base, name)`, `path.join`/`path.resolve`, `Path(base) / name`,
or string concatenation builds the path and nothing checks the result against
the root. `os.path.join("/srv", "/etc/passwd")` yields `/etc/passwd`; `..` in
the joined name survives un-checked.

## P4: archive member names not validated (Zip Slip)

`zipfile`/`tarfile`/`shutil.unpack_archive`/`yauzl`/`adm-zip`/`decompress`
style extraction writes member paths without a per-member check inside the
extract root. `tarfile.extractall` without `filter=`, `zf.extract(member)`,
and `open(os.path.join(dest, member.filename))` all land here when no
member-name guard exists in the enclosing function.

## P5: symlink/link escapes

Checklist class. Archive member link entries (`issym`/`islnk`/`linkname`,
`external_attr` DOS attributes, `tar` symlink entries), `os.symlink`/`os.link`
calls, and `realpath`-vs-`abspath` gaps can point writes outside the extract
root even when member names look clean. Deterministic only when a fixture
proves the static shape; otherwise every candidate is emitted for manual
verification.

## P6: platform path quirks

POSIX-only checks on paths a Windows (or mixed) deployment can feed:
`'..' in path.split("/")` (misses `..\`), textual `file:`/`file://` stripping
(`replace("file://", "")`, `removeprefix`), `:`-splitting that mishandles
drive letters or ADS (`file.txt:stream`), and `\\`/UNC handling gaps.
Deterministic where the shape is clear; platform matrix verification stays
manual.

## P7: URL/URI decoded into a path without re-validation

`unquote`, `unquote_plus`, `urlparse(u).path`, `url2pathname`,
`decodeURIComponent`, `new URL(u).pathname`: percent-encoding hides
`%2e%2e%2f` from every textual check, and a URI is not a filesystem path.
Decoding a caller-shaped value is the finding; whether it reaches a sink is
confirmed by the sibling site resolution.

## P8: weak, default-off, or bypassable root allowlist

Three deterministic sub-shapes:

- **Suffix/name allowlists**: `path.endswith(".jpg")`, unanchored
  `re.match`/`re.search` on the path, substring membership on a literal.
- **Env kill-switch**: an environment variable whose name reads as a guard
  bypass (`ALLOW_ANY_PATH`, `ALLOW_LOCAL*`, `DISABLE_PATH*`, `BYPASS*`,
  `UNSAFE`, `INSECURE`) read in code that guards caller-chosen paths.
- **Default-off allowlist**: a root/allowlist-shaped name
  (`allowed_paths`, `ALLOWED_*`, `permit*`) declared empty or `None`/`[]`
  by default, so the guard is a no-op until an operator opts in.

## P9: guard coverage across entry points

Checklist class. Every recognized entry point is emitted so a reviewer can
verify that each path from entry to sink shares the same complete guard: a
guarded `read_file` tool next to an unguarded `write_file` tool is two sites,
not one averaged verdict.

## P10: sensitive paths on a caller-influenced base

Checklist class. `open`/`readFile`-family calls touching credential-shaped
paths (`*.pem`, `id_rsa`, `.ssh`, `.aws/credentials`, `cookies`, `token`,
`secret`, `passwd`, `.env`) are emitted so a reviewer can confirm the base
directory is operator-fixed, not caller-chosen.
