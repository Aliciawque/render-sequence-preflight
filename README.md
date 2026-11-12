# render-sequence-preflight

A read-only, standard-library Python 3.11+ CLI for preflighting an **explicitly expected** render sequence. It finds missing first/last frames as well as interior gaps, empty files, unexpected frame numbers, padding variants and duplicate numeric frame identities. Its deterministic JSON and exit codes support CI or render-farm handoff checks.

This is metadata inventory, **not image validation**: it never decodes, opens, repairs or renders an image. A nonempty corrupt EXR can pass. It does not infer your intended range from files that happen to exist.

## Run

No dependencies or installation needed:

```sh
python3 preflight.py /path/to/renders --pattern 'beauty.{frame:04d}.exr' --start 1001 --end 1100
python3 preflight.py /path/to/renders --pattern 'beauty.{frame:04d}.exr' --start 1001 --end 1100 --json
python3 -m unittest -v
```

Runnable scratch example (these setup commands create files; the auditor does not):

```sh
scratch=$(mktemp -d)
printf x > "$scratch/beauty.1002.exr"
python3 preflight.py "$scratch" --pattern 'beauty.{frame:04d}.exr' --start 1001 --end 1003 --json
# exits 1: both expected boundaries are absent
```

## Contract

- Start and end are inclusive. Step is positive; end must be reachable exactly. At most 1,000,000 expected frames; accepted integer arguments are between `-(2**63-1)` and `2**63-1`. Negative frames work. For example, Python padding formats `-2` with width 4 as `-002` (sign counts toward width).
- Pattern is a plain filename, at most 255 characters, with exactly one `{frame}` or `{frame:0Nd}` field. Width N is 1–32. No directory separators, NUL, extra fields, conversions or nested formatting. Width is a minimum, not truncation.
- Only immediate children matching literal prefix/suffix and a signed decimal frame number are inventoried. Unrelated files and subdirectories are ignored. This is not a recursive tree or all-files security audit.
- Matching frame-number text longer than 128 characters is reported as unrepresentable and incomplete (exit 2); metadata for that entry is not inspected.
- A canonical filename is required for each expected frame. `beauty.1.exr` does not satisfy `beauty.0001.exr`. Both spellings together count as duplicate numeric identity. Plus signs and negative zero are reported as noncanonical.
- Matching symlinks and other nonregular entries are not followed and make the report incomplete. The supplied directory itself must not be a symlink. Ancestor paths are resolved normally by the OS; this is not a sandbox or defense against a concurrently malicious filesystem.
- Metadata or enumeration failures make the report incomplete, never clean. Missing results on an incomplete report are provisional. Files may change while being scanned: no atomic snapshot, content readability guarantee, stability window, checksum or corruption test is provided.
- JSON has `schema_version: 1`, input/range metadata, sorted `inventory`, `missing`, `findings`, and `errors`. Names are lexically ordered, duplicate groups and missing frames numerically ordered. No clock timestamps are emitted; identical observations at the same input path yield identical output. OS error strings can differ by platform.

Exit status:

| Code | Meaning |
|---|---|
| 0 | Complete metadata scan with no findings |
| 1 | Complete scan with missing frames or findings |
| 2 | Invalid input or incomplete scan |

`--json` prints an error object for semantic validation failures. CLI syntax/type errors are handled by argparse on stderr, exit 2, not JSON. No output file is written. File names are escaped in JSON, including in finding lines in human output.

## Design and scope

The intended handoff is “frames 1001 through 1100 must exist under this exact naming convention,” not discovering arbitrary sequences. Explicit bounds catch missing sequence endpoints that interior-gap-only checks cannot infer. A variant never silently fills an expected canonical path. Exit 2 takes priority over findings so automation cannot mistake an inaccessible or nonregular entry for a successful inventory.

Public inspiration and alternatives: [fileseq](https://github.com/justinfx/fileseq) provides rich VFX file-sequence parsing; [missing-render-frame-detector](https://github.com/alexanderson321/missing-render-frame-detector) describes interior missing-frame detection. This implementation was written independently, uses neither project's code nor dependencies, and does not claim to replace their broader workflows. Its narrow focus is explicit boundaries, fail-closed metadata inventory and CI reporting.

Tests cover real temporary files, command-line processes, boundaries, padding, duplicates, negative frames, strides, symlinks, directories, and mocked permission/metadata failures. No external programs are run by the auditor; no supplied filename or source is executed. Tested environments and limitations should be recorded with releases, not inferred from the suite.

MIT licensed. AI-assisted implementation and testing.
