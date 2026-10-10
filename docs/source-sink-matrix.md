# Source/sink matrix

This file is the documented detection boundary for the deterministic rules
under `rules/`. Every rule in the pack cites this file; the source, sink, and
sanitizer lists below are the contract the rules encode. If a rule and this
document disagree, the document is wrong until the rule changes.

The rules run on Semgrep Community Edition in taint mode. A P0 finding means:
a value derived from a caller-shaped path input reaches a filesystem sink
within one function body, and no recognized complete-guard call intervenes.

## Sources: caller-shaped path input

A source is a value a remote caller (or an upstream model, or an archive
writer) can plausibly shape: a parameter of a function registered as an entry
point, a path-named parameter, a path-named field read off a config, request,
upload, or payload object, or an archive member name. "Entry point" covers
every family the rules know: web route decorators and framework
registrations, tool registrations (MCP-style and otherwise), verb-named route
handlers, dispatch methods, and tool-class entry methods.

### Python (`path-guard-audit-p0-python` and later `rules/python/*`)

A parameter of a `def` or `async def` is a source when:

- Its name is path-shaped (case-insensitive): `path`, `filepath`,
  `file_path`, `file`, `filename`, `file_name`, `pathname`, `path_name`,
  `relative_path`, `rel_path`, `dest`, `dst`, `destination`, `target`,
  `name`, `key`, `object_key`, `member`, `member_name`, `entry`, `root`,
  `directory`, `dir`, `folder`. Suffix forms also match: `save_path`,
  `upload_path`, `out_file`, `memberName`, `fileName`, `objectKey`, and the
  same camel halves (`Path`, `File`, `Filename`, `Dir`, `Directory`,
  `Folder`, `Name`, `Key`, `Dest`, `Target`, `Member`, `Entry`). The camel
  halves are matched case-sensitively so `dump`/`dumpf`-style names stay
  out.
- The function carries a route decorator: `@<anything>.route`,
  `@<anything>.api_route`, `@<anything>.get|post|put|delete|patch|head|
  options|websocket`, `@<anything>.add_url_rule`, `@<anything>.api_view`,
  `@<anything>.action`, and the same names bare (`@route`, `@get`, ...),
  with or without call parens. Every parameter is a source.
- The function carries a tool-entry decorator: `@<anything>.tool`,
  `@<anything>.call_tool`, `@<anything>.get_prompt`, and the bare-name
  forms. Every parameter is a source; a tainted `arguments` dict taints
  every value extracted from it.
- The function is a dispatcher: its name starts with `execute`, `handle`,
  `dispatch`, `process`, `invoke`, `run`, or `call`, and one parameter is
  named `args`, `arguments`, `params`, `request`, or `input`.
- The function is a tool-entry method on a class whose name contains
  `tool` (case-insensitive): `forward`, `run`, `arun`, `call`, `execute`,
  `invoke`, `process`, or a name beginning with those, with an optional
  leading underscore (`_run`, `_execute`). Every parameter besides
  `self`/`cls` is a source, including `**kwargs`.

An expression is a source when it reads a path-shaped field:

- `<obj>.<member>` where the member is `path`, `filepath`, `file_path`,
  `filename`, `file_name`, `pathname`, `path_name`, `relative_path`,
  `dest`, `destination`, `target`, `object_key`, `member_name`, `linkname`,
  `originalfilename`, or `original_filename` (case-insensitive). Covers
  `file.filename`, `cfg.backup_path`, `tarinfo.linkname`,
  `upload.filename`.
- `<obj>.name` where the receiver name contains `member`, `entry`, `info`,
  `file`, `upload`, `part`, `blob`, `object`, `doc`, `asset`, `item`, or
  `resource` (case-insensitive). Covers `member.name`, `entry.name`,
  `zipinfo.filename`'s sibling form, `uploaded.name`, `part.name`. The
  receiver gate exists because `.name` on an arbitrary object is not a
  path.
- `<obj>.<member>` where the member is `name` and the receiver chain ends
  in `request`/`req` (`request.name`, `req.name`).
- `<obj>["<key>"]` or `<obj>.get("<key>", ...)` where the literal key is
  in the path-name set above (`path`, `filepath`, `file_path`, `filename`,
  `file_name`, `pathname`, `relative_path`, `dest`, `destination`,
  `target`, `name`, `key`, `object_key`, `member`, `entry`, `dir`,
  `directory`, `root`, `folder`). Covers `payload["path"]`,
  `args.get("filename")`, `config["backup_dir"]`.
- On a `request`/`req` receiver (or a dotted chain ending in one, such as
  `self.request`), reads of `args`, `GET`, `POST`, `query_params`,
  `path_params`, `form`, `data`, `json`, `params`, `values`, `query`,
  `body`, `files`, `FILES`, `stream`, or `headers` (case-sensitive member
  names, so `.get()` calls and `dict.get` helpers are not sources).
- Archive member enumerators: `<arc>.namelist()`, `<arc>.getnames()`,
  `<arc>.infolist()`, `<arc>.getmembers()` call results, and
  `<arc>.getinfo(<x>)`/`<arc>.getmember(<x>)` calls, are member-shaped
  sources (each extracted name/object is archive-writer shaped).

### TypeScript and JavaScript (`path-guard-audit-p0-typescript` and later `rules/typescript/*`)

A parameter is a source when:

- Its name is path-shaped: the same list as Python (case-insensitive),
  plus the same suffix and camel-half forms (`filePath`, `fileName`,
  `objectKey`, `memberName`, `destDir`, `targetPath`).
- The enclosing function is a verb-named handler: `GET`, `POST`, `PUT`,
  `DELETE`, `PATCH`, `HEAD`, or `OPTIONS` (function declaration or arrow
  assigned to the name), and the parameter is named `req`, `request`,
  `ctx`, or `event`. The Next.js route-handler shape.
- The enclosing callback is passed to a framework verb call:
  `<recv>.get|post|put|delete|del|patch|head|options|all|use|route|ws`
  (case-insensitive), arrow or `function` callback. Every callback
  parameter is a source, so `app.get("/p", (req, res) => ...)` taints
  `req` and `res` (response objects carry `sendFile`; a caller-chosen
  path argument reaches them through the handler).
- The enclosing callback is passed to a tool-registration method named
  `tool`, `registerTool`, `callTool`, `getPrompt`, `setRequestHandler`,
  `prompt`, or `resource`, on any receiver. Arrow functions with block or
  expression bodies, `function` expressions, and object-destructured
  parameters (`async ({ path }) => ...`, `async ({ path }: T) => ...`)
  are covered; destructured fields become individual sources.
- The enclosing function is a dispatcher: a method, function declaration,
  or object-literal callback whose name starts with `execute`, `handle`,
  `dispatch`, `process`, `invoke`, `run`, or `call`, with a parameter
  named `args`, `arguments`, `params`, `request`, or `input`.
- The enclosing signature destructures a path-named object field in a
  parameter: `function f({ path, name })`, `async run({ filePath }: T)`,
  arrow or method form, typed or not. Covers tool handlers that
  destructure their `arguments`/`input` object.

An expression is a source when it reads a caller-shaped field:

- `<obj>.<member>` where the member is in the path-name set above
  (case-insensitive), plus `originalname`, `originalName`, `fileName`,
  `filename`, `path`, `name` on gated receivers, `dest`, `destination`,
  `target`, `key`, `objectKey`. Covers `file.originalname`,
  `entry.path`, `req.query.path`, `opts.filename`.
- `<obj>["<key>"]` or `<obj>.get("<key>", ...)` for the same names.
  Covers `args["path"]`, `params["filename"]`, `searchParams.get("file")`.
- On a `req`/`request`/`ctx` receiver (or a dotted chain ending in one),
  reads and calls of `query`, `body`, `params`, `param`, `querystring`,
  `nextUrl`, `searchParams`, `formData`, `data`, `json`, `args`, `GET`,
  `POST`, `query_params`, `path_params`, `form`, `values`, `files`,
  `file`, or `request`. Covers `req.query.path`, `ctx.request.body`,
  `req.files`, `req.file`.
- Destructuring `const { ... } = <req-like>.<member>` where the member is
  `query`, `body`, `params`, `nextUrl`, `searchParams`, `formData`,
  `files`, or `file`: every destructured binding is a source. Covers
  `const { path } = req.query`.
- Destructuring `const { path } = <obj>` (also `let`, `var`, and bare
  assignment) where the destructured field name is path-shaped: the
  binding is a source from any object. Covers `const { filename } =
  payload`.
- Archive member enumerators: `<arc>.entries()`, `<arc>.getEntries()`,
  `<arc>.files`, and yauzl/unzipper-style `entry`/`file` event payloads
  (`zipfile.on("entry", (entry) => ...)`) where the member reads
  `entry.path`, `entry.fileName`, `entry.name`, `header.name` are
  archive-writer shaped.

## Sinks: filesystem and archive write/read/list calls

A sink is a call expression whose function position matches one of the
shapes below. The finding line is the sink call.

### Python

- `open(...)`, `os.open`, `io.open`, `codecs.open`, `builtins.open`,
  `gzip.open`, `bz2.open`, `lzma.open`, `tarfile.open`, `zipfile.ZipFile`
- `os.<method>` where the method is `remove`, `unlink`, `rename`,
  `replace`, `rmdir`, `removedirs`, `mkdir`, `makedirs`, `listdir`,
  `scandir`, `walk`, `truncate`, `chmod`, `chown`, `utime`, `link`,
  `symlink`, `readlink`, `mknod`, `open`, `stat`, `lstat`, `chdir`
- `shutil.<method>`: `copy`, `copy2`, `copyfile`, `copytree`, `move`,
  `rmtree`, `chown`, `unpack_archive`, `make_archive`
- `pathlib`/`Path` methods on any receiver: `open`, `read_text`,
  `read_bytes`, `write_text`, `write_bytes`, `mkdir`, `rename`,
  `replace`, `unlink`, `rmdir`, `iterdir`, `glob`, `rglob`, `symlink_to`,
  `link_to`, `hardlink_to`, `touch`, `chmod`, `exists`, `is_file`,
  `is_dir`, `stat`, `lstat`, `owner`, `expanduser`
- Web response helpers: `send_file`, `send_from_directory`, `sendfile`,
  `FileResponse`, `StaticFiles`, `send_from_directory`, `x_sendfile`
- Archive member sinks: `<arc>.extract(<member>, ...)`,
  `<arc>.extractall(...)`, `<arc>.extractfile(<member>)`,
  `shutil.unpack_archive`, `tarfile.open(...).extractall`
- `glob.glob`, `glob.iglob`, `fnmatch`-family when the arg is a path
- `tempfile`/`NamedTemporaryFile` are not sinks (system temp root is not
  caller-shaped)

### TypeScript and JavaScript

- `fs.<method>` and `fs/promises` equivalents: `readFile`, `writeFile`,
  `open`, `createReadStream`, `createWriteStream`, `unlink`, `rename`,
  `cp`, `copyFile`, `rm`, `rmdir`, `mkdir`, `readdir`, `access`,
  `mkdtemp`, `readlink`, `symlink`, `link`, `chmod`, `chown`, `utimes`,
  `truncate`, `appendFile`, plus their `*Sync` forms
- Bare calls named `readFile`, `writeFile`, `createReadStream`,
  `createWriteStream`, `sendFile`, `send` (covers direct imports and
  destructure-assigned fs helpers)
- Response helpers: `<res>.sendFile`, `<res>.download`,
  `<res>.sendfile`, `express.static`, `serveStatic`,
  `fastify.register(static)`, `<ctx>.sendFile`
- Archive member sinks: `<arc>.extract(<member>, ...)`,
  `<arc>.extractall(...)`, `unzipper.Extract`, `decompress(...)`,
  `tar.x`/`tar.extract`, `adm-zip` `extractAllTo`/`extractEntryTo`,
  member writes `fs.createWriteStream(path.join(dir, entry.path))`
- `<obj>.sendFile(<path>)`/`download(<path>)` on `res`-like receivers

## Sanitizers: the complete-guard call vocabulary

P0 is suppressed only by a call whose callee name matches the
complete-guard vocabulary. "Complete" means the guard canonicalizes the
path, enforces a root boundary, and handles platform quirks. Semgrep CE
cannot verify that pipeline inside a call, so the rule recognizes it by
name, matching this regular expression:

```text
(?i)((.*[._])?(safe_?join|safeJoin|is_?path_?inside|isPathInside|
assert_?under_?root|assertUnderRoot|resolve_?and_?check|resolveAndCheck|
within_?root|withinRoot|is_?within_?directory|isWithinDirectory|
is_?safe_?path|isSafePath|safe_?path|safePath|secure_?join|secureJoin|
resolve_?within|resolveWithin|assert_?inside|assertInside|
contained_?path|containedPath|is_?inside_?root|assert_?under_?base|
check_?path_?inside|guard_?path))[a-z_0-9]*
```

In words: callee names such as `safe_join(...)`, `safeJoin(...)`,
`is_path_inside(...)`, `assert_under_root(...)`, `resolve_and_check(...)`,
`within_root(...)`, `is_within_directory(...)`, `is_safe_path(...)`,
`secure_join(...)`, `resolve_within(...)`, `contained_path(...)`, and the
same shapes as methods (`self.assert_under_root(...)`,
`guards.safe_join(...)`, `werkzeug.utils.safe_join` imported direct). The
sanitizer is `by-side-effect` with `focus-metavariable` on the checked
argument (any position), so it covers both the return-value form
(`checked = safe_join(base, p)`) and the check-and-throw form
(`assert_under_root(p)`).

Everything not in that vocabulary leaves the value tainted. In particular
these do NOT sanitize: `os.path.join`, `os.path.normpath`,
`os.path.abspath`, `Path.resolve`, `os.path.realpath`, `startswith`,
`endswith`, `secure_filename`, `os.path.basename`, `urlparse`, `unquote`,
`re.sub`, `split`, `strip`, `Path`, and any other unrecognized name. That
is deliberate: a weak or unrecognized guard must not produce silence. The
raw P0 finding still fires, and the layered site resolution in
`classify.py` relabels or suppresses it.

## Layered site resolution (why weak guards still fire P0)

The taint rules produce raw candidate findings, not verdicts.
`classify.py` resolves each enumerated sink in order: a weak-class finding
(P1-P4, P6-P8) at the same site wins and the P0 finding is suppressed, so
a join-only site reports P3 and never double-labels as P0; otherwise a
complete-guard probe hit yields recognized-complete; otherwise an
intervening-call probe hit yields "guard detected, shape unrecognized,
manual review"; otherwise the site is P0. This is why the sanitizer
vocabulary above is intentionally narrow: anything the vocabulary misses
must stay tainted so the site can be classified instead of silently
passed.

## Analysis ceiling (what these rules cannot see)

Semgrep CE taint is intra-function. Known blind spots, all documented
rather than papered over:

- Helper-factored guards. A guard that lives in `paths.py` or
  `safeJoin.ts` and a sink in the caller do not share a taint path. The
  call to the helper shows up only through the intervening-call probe,
  so the site resolves to unrecognized-guard. Mature codebases will
  produce this verdict often; that is expected, not a miss.
- Helper-factored sinks. `await safeJoin(dir, p)` where `open` is called
  inside `safeJoin` produces no sink at all at the entry site. The same
  applies when a recognized tool-entry method delegates to a private
  helper (`_run` calling `self._write(path)`, which calls `open(path)`):
  the sink is enumerated but sits outside the entry extent, so it lands
  in the "outside recognized entries" review list rather than
  auto-classifying. Coverage reporting counts entry candidates and sinks
  separately so this cannot read as an empty scan.
- Factory-mounted and adapter guards. A complete guard attached to a
  storage object is invisible at the call site: a `Storage` whose
  `save()` resolves internally, or a session built by a guard factory,
  makes `storage.save(name)` look unguarded to lexical analysis. Do not
  treat those hits as unguarded; they are the ceiling this analyzer
  cannot see past.
- Parameter stickiness. A source parameter stays tainted for the whole
  function body: reassigning it (`path = "literal"`) or
  check-and-throwing on it directly (`assert_under_root(path)` then
  `open(path)`) does not clear the taint. The raw P0 finding fires; the
  complete-guard site probe resolves the site to recognized-complete at
  classify time. Locals derived from the parameter (`p = path`) CAN be
  cleaned by the check-and-throw sanitizer.
- Name-based complete-guard recognition is lexical. A callee name that
  collides with the vocabulary without being a full guard (for example a
  formatter named `safe_path`, or a `safe_join` that skips the boundary
  check) produces a false negative.
- Unlisted shapes are blind spots, not findings: entry points registered
  through shapes outside the matrix (for example custom registration
  lists) and filesystem clients not in the sink list (`sqlite3.connect`,
  `Pillow.Image.open` mid-list notwithstanding, `s3.get_object`) are
  counted by the coverage summary, not reported as guarded or unguarded.
- TOCTOU and symlink races. A guard checked before open has a window;
  proving the window is exploited requires dynamic timing and stays
  checklist (P5).

## Fixture contract

`semgrep test` treats the co-located fixture files as the executable form
of this matrix:

- `rules/python/*.py` and `rules/typescript/*.{ts,js}` next to each rule
- `tests/fixtures/p0/` holds small synthetic repos with the same shapes
  for CLI-level tests

Positive cases (annotated to fire): unguarded sinks in every source
shape, strip-only and join-only paths, archive member writes without
member checks, env-bypass and default-off allowlists, and the
parameter-stickiness ceiling case. Negative cases (annotated quiet):
recognized complete-guard calls in both forms, hardcoded literal paths,
sinks outside any recognized entry point, and sinks whose only inputs are
operator-fixed config values.
