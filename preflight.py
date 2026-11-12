"""Read-only metadata preflight for an explicitly bounded render sequence."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_FRAMES = 1_000_000
MAX_INTEGER = 2**63 - 1


class InvalidInput(ValueError):
    pass


def compile_pattern(pattern):
    if not isinstance(pattern, str) or len(pattern) > 255 or any(c in pattern for c in ('/', '\\', '\0')):
        raise InvalidInput('pattern must be a plain filename, at most 255 characters')
    match = re.fullmatch(r'([^{}]*)\{frame(?::0([1-9][0-9]?)d)?\}([^{}]*)', pattern)
    if not match:
        raise InvalidInput('pattern needs exactly one {frame} or {frame:0Nd} field')
    prefix, width, suffix = match.groups()
    if width is not None and int(width) > 32:
        raise InvalidInput('padding width must be 1 through 32')
    return re.compile(re.escape(prefix) + r'([+-]?[0-9]+)' + re.escape(suffix))


def audit(directory, pattern, start, end, step=1):
    matcher = compile_pattern(pattern)
    if any(type(n) is not int or abs(n) > MAX_INTEGER for n in (start, end, step)):
        raise InvalidInput('bounds and step must be signed 64-bit integers')
    if step <= 0 or end < start:
        raise InvalidInput('step must be positive and end must be >= start')
    if (end - start) % step:
        raise InvalidInput('end must be reachable from start with step')
    count = (end - start) // step + 1
    if count > MAX_FRAMES:
        raise InvalidInput(f'expected range exceeds {MAX_FRAMES} frames')
    report = {'schema_version': 1, 'directory': os.fspath(directory), 'pattern': pattern,
              'start': start, 'end': end, 'step': step, 'expected_count': count,
              'complete': True, 'inventory': [], 'missing': [], 'findings': [], 'errors': []}

    def error(name, reason):
        report['complete'] = False
        report['errors'].append({'name': name, 'reason': reason})

    try:
        mode = os.lstat(directory).st_mode
        if not stat.S_ISDIR(mode):
            error(None, 'directory must be a real directory, not a symlink')
            return report
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError as exc:
        error(None, f'{type(exc).__name__}: {exc.strerror}')
        return report
    seen = set()
    groups = {}
    for name in names:
        match = matcher.fullmatch(name)
        if not match:
            continue
        digits = match.group(1)
        if len(digits) > 128:
            report['findings'].append({'kind': 'unrepresentable_frame', 'name': name})
            error(name, 'frame number exceeds 128 characters; metadata not inspected')
            continue
        frame = int(digits)
        canonical = pattern.format(frame=frame)
        expected = start <= frame <= end and (frame - start) % step == 0
        groups.setdefault(frame, []).append(name)
        item = {'name': name, 'frame': frame, 'expected': expected, 'canonical': name == canonical}
        report['inventory'].append(item)
        if name == canonical:
            seen.add(frame)
        if not expected:
            report['findings'].append({'kind': 'unexpected_frame', 'name': name, 'frame': frame})
        if name != canonical:
            report['findings'].append({'kind': 'noncanonical_name', 'name': name, 'canonical_name': canonical})
        try:
            info = os.lstat(Path(directory) / name)
            if not stat.S_ISREG(info.st_mode):
                item['type'] = 'symlink' if stat.S_ISLNK(info.st_mode) else 'nonregular'
                error(name, 'matching entry is not a regular file (not followed)')
            else:
                item['type'] = 'regular'
                item['size'] = info.st_size
                if info.st_size == 0:
                    report['findings'].append({'kind': 'empty_file', 'name': name})
        except OSError as exc:
            error(name, f'{type(exc).__name__}: {exc.strerror}')
    for frame, names in sorted(groups.items()):
        if len(names) > 1:
            report['findings'].append({'kind': 'duplicate_frame', 'frame': frame, 'names': names})
    for frame in range(start, end + 1, step):
        if frame not in seen:
            report['missing'].append({'frame': frame, 'name': pattern.format(frame=frame),
                                      'position': 'boundary' if frame in (start, end) else 'interior'})
    return report


def exit_code(report):
    return 2 if not report['complete'] else int(bool(report['missing'] or report['findings']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--pattern', required=True)
    parser.add_argument('--start', type=int, required=True)
    parser.add_argument('--end', type=int, required=True)
    parser.add_argument('--step', type=int, default=1)
    parser.add_argument('--json', action='store_true', dest='as_json')
    args = parser.parse_args(argv)
    try:
        report = audit(args.directory, args.pattern, args.start, args.end, args.step)
    except (InvalidInput, OSError, ValueError) as exc:
        report = {'schema_version': 1, 'complete': False, 'missing': [], 'findings': [],
                  'errors': [{'name': None, 'reason': str(exc)}]}
    code = exit_code(report)
    if args.as_json:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    else:
        print(('CLEAN', 'FINDINGS', 'INCOMPLETE / INVALID')[code])
        for item in report['missing']:
            print(f"missing {item['position']}: {item['name']!r}")
        for item in report['findings']:
            print(json.dumps(item, sort_keys=True))
        for item in report['errors']:
            print(f"error: {item['name'] or '(directory/input)'}: {item['reason']}")
        print(f"{len(report['missing'])} missing; {len(report['findings'])} findings; {len(report['errors'])} errors")
    return code


if __name__ == '__main__':
    sys.exit(main())
