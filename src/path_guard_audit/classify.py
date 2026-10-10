"""Layered site resolution over raw semgrep results.

Raw semgrep results are inputs, not verdicts. This module groups them by
enclosing entry point (the site) and resolves each site in precedence order:

1. a weak-class deterministic finding (any ``metadata.guard_class`` other
   than the no-guard class) wins; the raw no-guard finding at the same
   site is suppressed so a scheme-only site reports its weak class and
   never double-labels as P0;
2. otherwise a raw no-guard finding plus a *bound* complete-guard probe
   hit yields recognized-complete;
3. otherwise a raw no-guard finding plus a *bound* intervening-validation
   probe hit yields unrecognized-guard ("guard detected, shape
   unrecognized, manual review");
4. otherwise the raw no-guard finding stands as a P0 finding.

A probe hit is *bound* when identifiers in its matched line overlap the
sink call's first-argument identifiers: ``assert_under_root(p)`` binds
to ``requests.get(url)``; ``safe_join("/srv", "static")`` or
``check_quota(1)`` in the same extent do not, so an unrelated
guard-shaped call can neither launder a site into recognized-complete
nor downgrade it to unrecognized-guard. A complete-guard probe hit with
no raw no-guard finding means the by-side-effect sanitizer cleaned the
tainted value, so the site resolves recognized-complete without the
binding check.

The module is data-driven off rule metadata: it reads
``metadata.guard_class`` and ``metadata.probe_role`` and never names a
rule id, so class rules added later integrate without code changes.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# Probe roles emitted via metadata.probe_role by rules/site-probes and
# rules/checklist.
ROLE_HANDLER = "handler_source"
ROLE_SINK = "path_sink"
ROLE_COMPLETE_GUARD = "complete_guard"
ROLE_INTERVENING = "intervening_validation"
ROLE_CHECKLIST = "checklist"
# In-function canonical-boundary pair: a variable assigned from a
# canonicalizing call (realpath/abspath/normpath/resolve) that an `if`
# reject-arm boundary-checks with a separator-joined prefix or
# is_relative_to. Stricter than a named guard call: the rule only fires
# when the checked variable is itself canonicalized, and resolution
# additionally requires that variable to reach a sink's first argument.
ROLE_CANON_BOUNDARY = "canonical_boundary_guard"

# The no-guard baseline class. Every other guard_class value on a
# deterministic-tier result is a weak class that outranks it at a site.
NO_GUARD_CLASS = "P0"

# Classes a bound canonical-boundary guard can clear: the join/member
# classes (P2 prefix-without-canonicalization, P3 join-without-boundary,
# P4 member traversal) all name the gap a canonicalize + boundary check
# fills. Other classes name different bugs (P1 strip-only shaping, P7
# decoded inputs, P8 env allowlists) that the same check does not cure,
# so a site carrying them stays deterministic.
_CANON_BOUNDARY_CLASSES = frozenset({"P2", "P3", "P4"})

# Bulk-extract calls whose member-name safety lives inside the
# dependency and cannot be verified intra-function. When a P4 finding's
# matched call is one of these methods AND the file references the
# package, the finding is demoted out of the deterministic class set into
# a dependency-guard note: ``unverified`` resolves the site
# unrecognized_guard ("dependency-guarded, verify version"), a manifest
# pin at or above the minimum records the version as evidence, and a pin
# *below* the minimum leaves the P4 in place.
_DEP_GUARDED_EXTRACTORS = {
    # adm-zip >= 0.6.1 runs every entry name through Utils.canonical +
    # Utils.sanitize (containment under the target root) and
    # filetools.assertPathSafe (rejects writes through pre-existing
    # in-root symlinks). Older versions sanitize names but followed
    # destination symlinks (CVE-2026-76845 / GHSA-vwc7-r8mq-g2x9), and
    # pre-0.5.10 lacked even the name check (GHSL-2020-198).
    "extractAllTo": ("adm-zip", (0, 6, 1)),
    "extractAllToAsync": ("adm-zip", (0, 6, 1)),
    "extractEntryTo": ("adm-zip", (0, 6, 1)),
    "extractEntryToAsync": ("adm-zip", (0, 6, 1)),
}

_DEP_METHOD_RE = re.compile(
    r"\.(" + "|".join(sorted(_DEP_GUARDED_EXTRACTORS)) + r")\s*\("
)
_DEP_PKG_NEEDLES = {"adm-zip": re.compile(r"adm-zip|AdmZip")}
# Exact-pins only count as version evidence; a range (^, ~, >=) does not
# prove what got installed.
_EXACT_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

RESOLUTION_DETERMINISTIC = "deterministic"
RESOLUTION_RECOGNIZED_COMPLETE = "recognized_complete"
RESOLUTION_UNRECOGNIZED = "unrecognized_guard"
RESOLUTION_NO_FLOW = "no_source_flow"
RESOLUTION_HANDLER_NO_SINK = "source_no_sink"

# Path segments that flag a finding as living under a test/example tree
# (flagged, never dropped).
_TEST_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "__tests__",
        "spec",
        "specs",
        "e2e",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "demo",
        "demos",
        "docs",
        "doc",
    }
)

_EXT_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Boundary-check call subjects inside a canonical-boundary probe hit:
# `v.startswith(<arg containing a separator join>)`, `v.startsWith(...)`,
# `v.is_relative_to(root)`. A startswith whose argument lacks a
# separator join is not a boundary check and is ignored, so a second,
# unrelated startswith in the same condition cannot smuggle its subject
# into the bound-variable set.
_CHECKED_VAR_RE = re.compile(
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*"
    r"(startswith|startsWith|is_relative_to|relative_to)\s*\("
)


def _balanced_arg(text: str, open_paren: int) -> str:
    """Text between ``text[open_paren]`` and its matching close paren."""
    depth = 0
    end = len(text)
    for j in range(open_paren, len(text)):
        c = text[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                end = j
                break
    return text[open_paren + 1 : end]


def _canon_checked_vars(text: str) -> set[str]:
    """Variables boundary-checked by a canonical-boundary probe hit.

    The probe matched an ``if`` statement; the checked variable is the
    subject of the separator-joined prefix or is_relative_to call inside
    its condition.
    """
    out: set[str] = set()
    for m in _CHECKED_VAR_RE.finditer(text):
        method = m.group(2)
        if method in ("startswith", "startsWith"):
            arg = _balanced_arg(text, m.end() - 1)
            if not ("sep" in arg or '"/"' in arg or "'/'" in arg):
                continue
        out.add(m.group(1))
    return out


def _manifest_dep_version(
    target_root: Path | None, package: str
) -> str | None:
    """Exact installed version of ``package`` from target manifests.

    Consults package-lock.json (resolved ``node_modules/<pkg>`` version)
    and package.json (exact pins only; ranges prove nothing). Returns
    None when no evidence exists. Cheap and offline: two JSON reads at
    the target root, no registry contact.
    """
    import json as _json

    if target_root is None:
        return None
    root = target_root if target_root.is_dir() else target_root.parent
    lock = root / "package-lock.json"
    if lock.is_file():
        try:
            data = _json.loads(lock.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError):
            data = {}
        version = (
            (data.get("packages") or {})
            .get(f"node_modules/{package}", {})
            .get("version")
        )
        if version is None:
            version = (
                (data.get("dependencies") or {}).get(package, {}).get("version")
            )
        if isinstance(version, str) and _EXACT_VERSION.match(version):
            return version
    manifest = root / "package.json"
    if manifest.is_file():
        try:
            data = _json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError):
            data = {}
        for section in ("dependencies", "devDependencies"):
            spec = (data.get(section) or {}).get(package)
            if isinstance(spec, str) and _EXACT_VERSION.match(spec):
                return spec
    return None


def _version_tuple(version: str) -> tuple[int, ...] | None:
    m = _EXACT_VERSION.match(version)
    return tuple(int(g) for g in m.groups()) if m else None


def _dependency_guard_note(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> dict | None:
    """Dependency-guarded extractor note, or None to keep the P4.

    Fires when a P4 finding's matched call is a known self-sanitizing
    extractor method and the file references that package. Demotion is
    conservative: a manifest pin *below* the extractor's minimum safe
    version leaves the deterministic P4 untouched; no evidence and a
    safe pin both produce a note, with the reason string saying which.
    """
    text = _hit_text(result, target_root, lines_cache)
    m = _DEP_METHOD_RE.search(text)
    if not m:
        return None
    package, minimum = _DEP_GUARDED_EXTRACTORS[m.group(1)]
    file_lines = _file_lines(
        result.get("path", ""), target_root, lines_cache
    )
    haystack = "\n".join(file_lines) if file_lines else text
    if not _DEP_PKG_NEEDLES[package].search(haystack):
        return None
    loc = _loc(result)
    version = _manifest_dep_version(target_root, package)
    if version is not None:
        vt = _version_tuple(version)
        if vt is not None and vt < minimum:
            # Evidence says the installed extractor predates the
            # sanitizer: the member-slip risk is real, keep the P4.
            return None
        reason = (
            f"dependency-guarded: {package} {version} "
            f"(manifest pin) >= {'.'.join(map(str, minimum))} "
            "sanitizes member names at extraction"
        )
        status = "confirmed"
    else:
        reason = (
            f"dependency-guarded, verify version: {package}>="
            f"{'.'.join(map(str, minimum))} sanitizes member names at "
            "extraction; installed version not verified (no "
            "package-lock/package.json evidence)"
        )
        status = "unverified"
    return {
        **loc,
        "package": package,
        "min_version": ".".join(map(str, minimum)),
        "version": version,
        "version_status": status,
        "reason": reason,
    }

# Keywords and literals excluded from identifier extraction when binding
# probe hits to sink arguments.
_NONARG_WORDS = frozenset(
    {
        "if", "else", "elif", "raise", "throw", "return", "not", "and",
        "or", "in", "is", "new", "const", "let", "var", "def", "await",
        "async", "for", "while", "try", "except", "finally", "with",
        "True", "False", "None", "true", "false", "null", "undefined",
        "function",
    }
)

# Control characters stripped from matched text before it is rendered as
# a site label or checklist message in terminal output.
_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def is_test_path(path: str) -> bool:
    """True when ``path`` sits under a test/example tree or names one."""
    p = PurePosixPath(path.replace("\\", "/"))
    lowered = [seg.lower() for seg in p.parts]
    if any(seg in _TEST_SEGMENTS for seg in lowered):
        return True
    name = lowered[-1] if lowered else ""
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _language_of(path: str) -> str:
    return _EXT_LANGUAGE.get(PurePosixPath(path).suffix.lower(), "other")


def class_sort_key(cls: str) -> tuple[int, str]:
    """Numeric ordering for ``P<N>`` labels so P10 sorts after P9."""
    if len(cls) > 1 and cls[1:].isdigit():
        return (int(cls[1:]), cls)
    return (10**6, cls)


def _loc(result: dict) -> dict:
    start = result.get("start") or {}
    return {
        "path": result.get("path", ""),
        "line": start.get("line", 0),
        "col": start.get("col", 0),
    }


def _extent(result: dict) -> tuple[int, int]:
    start = (result.get("start") or {}).get("line", 0)
    end = (result.get("end") or {}).get("line", start)
    return start, end


def _file_lines(
    rel: str,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> list[str] | None:
    """Read a result file's lines once, cached per resolved path.

    Semgrep reports paths as given on the command line: absolute targets
    yield absolute result paths, relative targets yield cwd-relative
    ones. Try both the raw path and the target-root join.
    """
    candidates = [Path(rel)]
    if target_root is not None:
        candidates.append(target_root / rel)
        try:
            candidates.append(target_root / Path(rel).relative_to(target_root))
        except ValueError:
            pass
    seen: set[str] = set()
    for src in candidates:
        key = str(src)
        if key in seen:
            continue
        seen.add(key)
        if key not in lines_cache:
            try:
                lines_cache[key] = src.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                lines_cache[key] = None
        if lines_cache[key] is not None:
            return lines_cache[key]
    return None


def _hit_text(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> str:
    """Full source text of the lines spanned by a result's match.

    Prefers the target file so an enclosing assignment target is visible
    (``checked = assert_under_root(p)``); falls back to semgrep's
    ``extra.lines`` when the file is unreadable.
    """
    start = result.get("start") or {}
    end = result.get("end") or {}
    file_lines = _file_lines(result.get("path", ""), target_root, lines_cache)
    if file_lines is not None:
        s_line, e_line = start.get("line", 0), end.get("line", 0)
        if 0 < s_line <= len(file_lines):
            e_line = min(max(e_line, s_line), len(file_lines))
            return "\n".join(file_lines[s_line - 1 : e_line])
    return (result.get("extra") or {}).get("lines") or ""


def _first_arg_idents(text: str) -> set[str]:
    """Identifiers in the first top-level argument of a call expression.

    For ``requests.get(url, headers=h)`` this is ``{url}``: the URL
    argument, not incidental kwargs. Falls back to every identifier in
    the text when the hit is not a call (e.g. an ``if`` check-and-throw).
    """
    i = text.find("(")
    if i == -1:
        region = text
    else:
        depth = 0
        end = len(text)
        for j in range(i, len(text)):
            c = text[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            elif c == "," and depth == 1:
                end = j
                break
        region = text[i + 1 : end]
    return {
        m for m in _IDENT.findall(region) if m not in _NONARG_WORDS
    }


def _text_idents(text: str) -> set[str]:
    return {
        m for m in _IDENT.findall(text) if m not in _NONARG_WORDS
    }


def _function_hint(
    result: dict,
    target_root: Path | None,
    lines_cache: dict[str, list[str] | None],
) -> str:
    """First line of the matched region, trimmed, for site labeling.

    Semgrep's JSON leaves ``extra.lines`` as "requires login", so the
    label line is read from the target file when a root is given. Control
    characters are stripped: matched text is attacker-controlled bytes on
    its way to a terminal.
    """
    lines = ((result.get("extra") or {}).get("lines") or "").strip()
    if lines and lines != "requires login":
        return _CTRL_CHARS.sub("", lines.splitlines()[0])[:80]
    line_no = (result.get("start") or {}).get("line", 0)
    file_lines = _file_lines(result.get("path", ""), target_root, lines_cache)
    if file_lines is not None and 0 < line_no <= len(file_lines):
        return _CTRL_CHARS.sub("", file_lines[line_no - 1].strip())[:80]
    return ""


@dataclass
class _Site:
    path: str
    start_line: int
    end_line: int
    label: str = ""
    sinks: list[dict] = field(default_factory=list)
    # Raw sink results, kept for argument-identifier binding.
    sink_results: list[dict] = field(default_factory=list)
    # Identifiers from sink first arguments; synthetic sites (a class
    # finding outside every entry extent) seed this from the finding's
    # own call text.
    sink_arg_idents: set[str] = field(default_factory=set)
    # guard_class -> list of finding locations at this site
    class_locations: dict[str, list[dict]] = field(default_factory=dict)
    has_raw_no_guard: bool = False
    no_guard_locations: list[dict] = field(default_factory=list)
    complete_guard_results: list[dict] = field(default_factory=list)
    validation_results: list[dict] = field(default_factory=list)
    canon_guard_results: list[dict] = field(default_factory=list)
    # P4 findings demoted because the extractor call is a documented
    # self-sanitizing dependency API; each entry is the note dict from
    # _dependency_guard_note.
    dep_guards: list[dict] = field(default_factory=list)
    resolution: str = ""
    test_path: bool = False

    @property
    def key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.end_line)

    @property
    def classes(self) -> list[str]:
        return sorted(self.class_locations, key=class_sort_key)

    def to_record(self) -> dict:
        guards: list[dict] = []
        for r in (
            self.complete_guard_results
            + self.validation_results
            + self.canon_guard_results
        ):
            loc = _loc(r)
            if loc not in guards:
                guards.append(loc)
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "site": self.label,
            "resolution": self.resolution,
            "classes": self.classes,
            "class_locations": {
                cls: self.class_locations[cls]
                for cls in sorted(self.class_locations, key=class_sort_key)
            },
            "sinks": self.sinks,
            "guard_locations": guards,
            "dependency_guards": self.dep_guards,
            "test_path": self.test_path,
        }


def classify_results(
    scan_data: dict,
    *,
    target_ignore_files: list[str] | None = None,
    excluded_dirs: list[str] | None = None,
    target_root: str | Path | None = None,
) -> dict:
    """Resolve raw semgrep JSON into sites, checklist, and coverage.

    ``scan_data`` is the parsed semgrep ``--json`` payload. Returns a dict
    with keys ``sites``, ``checklist``, ``coverage``.
    """
    root = Path(target_root) if target_root is not None else None
    results = scan_data.get("results") or []
    lines_cache: dict[str, list[str] | None] = {}

    entries: dict[str, list[dict]] = {}
    sinks: dict[str, list[dict]] = {}
    complete_hits: dict[str, list[dict]] = {}
    validation_hits: dict[str, list[dict]] = {}
    canon_hits: dict[str, list[dict]] = {}
    checklist_hits: list[dict] = []
    class_findings: list[tuple[str, dict]] = []
    dep_findings: list[dict] = []

    for r in results:
        meta = (r.get("extra") or {}).get("metadata") or {}
        role = meta.get("probe_role")
        guard_class = meta.get("guard_class")
        path = r.get("path", "")
        if role == ROLE_HANDLER:
            entries.setdefault(path, []).append(r)
        elif role == ROLE_SINK:
            sinks.setdefault(path, []).append(r)
        elif role == ROLE_COMPLETE_GUARD:
            complete_hits.setdefault(path, []).append(r)
        elif role == ROLE_INTERVENING:
            validation_hits.setdefault(path, []).append(r)
        elif role == ROLE_CANON_BOUNDARY:
            canon_hits.setdefault(path, []).append(r)
        elif role == ROLE_CHECKLIST or meta.get("tier") == "checklist":
            checklist_hits.append(r)
        elif guard_class:
            note = None
            if str(guard_class) == "P4":
                note = _dependency_guard_note(r, root, lines_cache)
            if note is not None:
                dep_findings.append((note, r))
            else:
                class_findings.append((str(guard_class), r))
        # Results with neither probe_role nor guard_class are foreign to
        # the pack and ignored by the pipeline.

    # Build sites: one per entry-point extent, then attach sinks, probes, and
    # class findings whose lines fall inside the extent.
    sites: dict[tuple[str, int, int], _Site] = {}
    sites_by_path: dict[str, list[_Site]] = {}

    def site_for(path: str, line: int) -> _Site | None:
        best: _Site | None = None
        for s in sites_by_path.get(path, ()):
            if s.start_line <= line <= s.end_line:
                if best is None or (s.end_line - s.start_line) < (
                    best.end_line - best.start_line
                ):
                    best = s
        return best

    for path, hs in entries.items():
        for h in hs:
            start, end = _extent(h)
            key = (path, start, end)
            if key not in sites:
                site = _Site(
                    path=path,
                    start_line=start,
                    end_line=end,
                    label=_function_hint(h, root, lines_cache),
                    test_path=is_test_path(path),
                )
                sites[key] = site
                sites_by_path.setdefault(path, []).append(site)

    sinks_outside_entries: list[dict] = []
    for path, ss in sinks.items():
        for s in ss:
            loc = _loc(s)
            site = site_for(path, loc["line"])
            if site is None:
                sinks_outside_entries.append(loc)
            elif loc not in site.sinks:
                site.sinks.append(loc)
                site.sink_results.append(s)

    for path, hs in complete_hits.items():
        for h in hs:
            loc = _loc(h)
            site = site_for(path, loc["line"])
            if site is not None and loc not in [
                _loc(r) for r in site.complete_guard_results
            ]:
                site.complete_guard_results.append(h)

    for path, vs in validation_hits.items():
        for v in vs:
            loc = _loc(v)
            site = site_for(path, loc["line"])
            if site is not None and loc not in [
                _loc(r) for r in site.validation_results
            ]:
                site.validation_results.append(v)

    for path, cs in canon_hits.items():
        for c in cs:
            loc = _loc(c)
            site = site_for(path, loc["line"])
            if site is not None and loc not in [
                _loc(r) for r in site.canon_guard_results
            ]:
                site.canon_guard_results.append(c)

    for cls, f in class_findings:
        loc = _loc(f)
        site = site_for(f.get("path", ""), loc["line"])
        if site is None:
            # A deterministic finding outside every recognized entry
            # extent still must not go silent: give it a synthetic site
            # spanning the finding itself.
            start, end = _extent(f)
            site = _Site(
                path=f.get("path", ""),
                start_line=start,
                end_line=end,
                label=_function_hint(f, root, lines_cache),
                test_path=is_test_path(f.get("path", "")),
            )
            # The finding's own call is the site's sink for binding:
            # guard arguments must overlap its first-argument identifiers.
            site.sink_arg_idents = _first_arg_idents(
                _hit_text(f, root, lines_cache)
            )
            sites[site.key] = site
            sites_by_path.setdefault(site.path, []).append(site)
        if cls == NO_GUARD_CLASS:
            site.has_raw_no_guard = True
            if loc not in site.no_guard_locations:
                site.no_guard_locations.append(loc)
        else:
            site.class_locations.setdefault(cls, [])
            if loc not in site.class_locations[cls]:
                site.class_locations[cls].append(loc)

    for note, f in dep_findings:
        loc = _loc(f)
        site = site_for(f.get("path", ""), loc["line"])
        if site is None:
            # Same don't-go-silent rule as orphan class findings: a
            # demoted dependency-guarded sink outside every recognized
            # entry extent gets a synthetic site so the note is visible.
            start, end = _extent(f)
            site = _Site(
                path=f.get("path", ""),
                start_line=start,
                end_line=end,
                label=_function_hint(f, root, lines_cache),
                test_path=is_test_path(f.get("path", "")),
            )
            sites[site.key] = site
            sites_by_path.setdefault(site.path, []).append(site)
        site.dep_guards.append(note)

    # Layered resolution per site (precedence: weak class > bound
    # recognized-complete > bound unrecognized-guard > raw no-guard).
    # Sites with a sink but no tainted source-input flow are recorded,
    # not reported. Binding: probe hits only upgrade or downgrade a
    # no-guard site when their matched line shares an identifier with a
    # sink call's first argument, so a guard-shaped call on an unrelated
    # value can neither launder the site into recognized-complete nor
    # relabel it unrecognized-guard.
    for site in sites.values():
        if (
            not site.sinks
            and not site.class_locations
            and not site.has_raw_no_guard
            and not site.dep_guards
        ):
            # Handler with no enumerated sink: a surface marker only.
            site.resolution = RESOLUTION_HANDLER_NO_SINK
            continue
        sink_args = site.sink_arg_idents or {
            ident
            for s in site.sink_results
            for ident in _first_arg_idents(
                _hit_text(s, root, lines_cache)
            )
        }

        def bound(results: list[dict]) -> bool:
            if not sink_args:
                return False
            return any(
                _text_idents(_hit_text(r, root, lines_cache)) & sink_args
                for r in results
            )

        def canon_bound() -> bool:
            # Strict binding for canonical-boundary probes: the
            # *checked* variable (not just any identifier in the `if`)
            # must appear in a sink's first argument, so a guard on an
            # unrelated value cannot launder the site.
            if not sink_args:
                return False
            for r in site.canon_guard_results:
                checked = _canon_checked_vars(
                    _hit_text(r, root, lines_cache)
                )
                if checked & sink_args:
                    return True
            return False

        if site.class_locations:
            if set(site.class_locations) <= _CANON_BOUNDARY_CLASSES and (
                canon_bound()
            ):
                # In-function canonicalize + boundary-check guard: the
                # join/member classes at this site name exactly the gap
                # this shape closes.
                site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
            else:
                site.resolution = RESOLUTION_DETERMINISTIC
        elif site.has_raw_no_guard:
            if bound(site.complete_guard_results) or canon_bound():
                site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
            elif bound(site.validation_results):
                site.resolution = RESOLUTION_UNRECOGNIZED
            else:
                site.class_locations[NO_GUARD_CLASS] = [
                    dict(s) for s in site.no_guard_locations
                ]
                site.resolution = RESOLUTION_DETERMINISTIC
        elif site.complete_guard_results or site.canon_guard_results:
            # No raw no-guard finding means the by-side-effect sanitizer
            # cleaned the tainted value itself; the guard vocabulary was
            # seen at this site.
            site.resolution = RESOLUTION_RECOGNIZED_COMPLETE
        elif site.dep_guards:
            # Every deterministic class was demoted to a dependency-guard
            # note: "dependency-guarded, verify version" goes to manual
            # review, never silent.
            site.resolution = RESOLUTION_UNRECOGNIZED
        else:
            site.resolution = RESOLUTION_NO_FLOW

    ordered_sites = sorted(sites.values(), key=lambda s: s.key)
    site_records = [s.to_record() for s in ordered_sites]

    # Checklist items, deduplicated by (class, path, line). Emitted when
    # anything path-relevant was detected: a recognized entry point, a
    # sink, or a checklist candidate itself (wholly empty scans
    # stay quiet, and counting candidates keeps checklist-tier corpus
    # instances validatable).
    checklist: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for r in checklist_hits:
        meta = (r.get("extra") or {}).get("metadata") or {}
        loc = _loc(r)
        key = (str(meta.get("guard_class") or "?"), loc["path"], loc["line"])
        if key in seen:
            continue
        seen.add(key)
        checklist.append(
            {
                "class": key[0],
                "path": loc["path"],
                "line": loc["line"],
                "verify": meta.get("verify") or "",
                "message": ((r.get("extra") or {}).get("message") or "").strip(),
                "test_path": is_test_path(loc["path"]),
            }
        )
    checklist.sort(key=lambda i: (class_sort_key(i["class"]), i["path"], i["line"]))

    # Coverage. "path surface" for the verdict means recognized
    # entry points, filesystem sinks, or checklist candidates -- all three are
    # path-relevant evidence.
    scanned = (scan_data.get("paths") or {}).get("scanned") or []
    by_lang = Counter(_language_of(p) for p in scanned)

    entry_candidates = sum(len(v) for v in entries.values())
    sinks_found = sum(len(v) for v in sinks.values())
    path_surface = (
        entry_candidates > 0 or sinks_found > 0 or bool(checklist)
    )

    parse_failures = [
        {
            "path": e.get("path") or "",
            "message": e.get("message") or str(e.get("type") or e),
        }
        for e in (scan_data.get("errors") or [])
        if isinstance(e, dict)
    ]

    # A scan that produced only errors analyzed nothing: "no path
    # detected" would claim the files were analyzed and clean, so an
    # all-failed run reports analysis_incomplete (the CLI maps that to
    # the operational-failure exit code).
    if path_surface:
        verdict = "surface_detected"
    elif not scanned and parse_failures:
        verdict = "analysis_incomplete"
    else:
        verdict = "no_path_surface_detected"

    by_resolution = Counter(s["resolution"] for s in site_records)

    coverage = {
        "files_scanned": {
            "total": len(scanned),
            **{lang: by_lang[lang] for lang in sorted(by_lang)},
        },
        "entry_candidates": entry_candidates,
        "sinks_found": sinks_found,
        "sinks_outside_recognized_entries": sorted(
            sinks_outside_entries, key=lambda l: (l["path"], l["line"])
        ),
        "parse_failures": parse_failures,
        "checklist_candidates": len(checklist),
        "target_ignore_files": list(target_ignore_files or []),
        "excluded_dirs": sorted(excluded_dirs or []),
        "sites": site_records,
        "sites_by_resolution": by_resolution,
        "verdict": verdict,
    }
    return {"sites": site_records, "checklist": checklist, "coverage": coverage}
