#!/usr/local/bin/python3

"""
This script identifies all duplicate copies of files across the system.

<3 Matt
"""

import collections
import os
import pathlib
import sys

import xxhash


assert sys.version_info >= (3, 6, 0)


FILES_FOUND = 0
FILES_SIZED = 0
FILES_SCANNED = 0
BYTES_SCANNED = 0
DUPLICATE_FILES = 0
DUPLICATE_BYTES = 0

SIZE_MIN = 1 * 1024 * 1024


def safe_percent(num, denom):
    if not denom:
        return "n/a"
    return f"{num / denom:.1%}"


def human_bytes(n):
    """Return the given bytes as a human-friendly string"""

    step = 1024
    abbrevs = ['KB', 'MB', 'GB', 'TB']

    if n < step:
        return f"{n}B"

    for abbrev in abbrevs:
        n /= step
        if n < step:
            break

    return f"{n:.2f}{abbrev}"


def fast_hash(path, buffer=1024*1024):
    """
    Hashes the contents of the given filepath in chunks.
    Returns a hex digest (0-9a-f) of the SHA256 hash.
    Performance on a Macbook Pro is about 384 MB/s.
    """

    hash_obj = xxhash.xxh64()

    with open(path, "rb") as infile:
        data = infile.read(buffer)
        while data:
            hash_obj.update(data)
            data = infile.read(buffer)

    return hash_obj.hexdigest()


def scantree(path):
    """Recursively yield DirEntry objects for given directory."""
    if str(path).startswith('.'):
        return

    try:
        entries = os.scandir(path)
    except PermissionError:
        print(f"No permission to scan {str(path)}")
        entries = []

    for entry in entries:
        if entry.name.startswith('.'):
            continue

        if entry.is_symlink():
            continue

        elif entry.is_dir():
            yield from scantree(entry.path)
        else:
            yield entry


def yield_entries(path):
    global FILES_FOUND

    gen = scantree(path)
    for entry in gen:

        filename = entry.name
        if filename.startswith('.'):
            continue

        # elif str(filepath).endswith("__init__.py"):
        #     continue
        # elif str(filepath).endswith(".pyc"):
        #     continue

        FILES_FOUND += 1
        if not FILES_FOUND % 100:
            sys.stdout.write(f"{FILES_FOUND} files found\r")
        yield entry


def group_matches_by(filepaths, func):
    groups = collections.defaultdict(list)
    for filepath in filepaths:
        group = func(filepath)
        groups[group].append(filepath)

    for (key, val) in list(groups.items()):
        if len(val) == 1:
            del groups[key]

    return groups


def get_path():
    try:
        path = sys.argv[1]
    except IndexError:
        path = os.environ["SAVED_PWD"]

    path = pathlib.Path(path)

    inp = input(f"Dedupe will recursively search '{path}'.\nIs that ok? [Y/n] ")
    if inp not in 'Yy':
        print("Cancelling.")
        exit(1)

    assert path.exists()
    return path


def main():
    global FILES_FOUND
    global FILES_SIZED
    global FILES_SCANNED
    global BYTES_SCANNED
    global DUPLICATE_FILES
    global DUPLICATE_BYTES

    path = get_path()

    all_entries = yield_entries(path)

    sizes = group_matches_by(all_entries, lambda e: e.stat().st_size)
    if 0 in sizes:
        del sizes[0]

    print("\n\n")
    for (size, entries_by_size) in sorted(sizes.items()):
        FILES_SIZED += len(entries_by_size)
        if size < SIZE_MIN:
            continue

        FILES_SCANNED += len(entries_by_size)
        human_size = human_bytes(size)

        if (entries_by_digest := group_matches_by(entries_by_size, fast_hash)):
            duplicate_entries_across_digests = 0
            duplicate_bytes_across_digests = 0

            print(f"Group {size} ({human_size})")
            for (idx, (digest, entries)) in enumerate(entries_by_digest.items()):
                if idx:
                    print()

                duplicate_entries = len(entries) - 1
                duplicate_bytes = size * duplicate_entries
                read_bytes = duplicate_bytes + size

                duplicate_entries_across_digests += duplicate_entries
                duplicate_bytes_across_digests += duplicate_bytes

                DUPLICATE_BYTES += duplicate_bytes
                BYTES_SCANNED += read_bytes

                print(f"  Digest {digest}")
                for entry in entries:
                    print(f"    {entry.path}")
                print(f"  (x{duplicate_entries} = {human_bytes(duplicate_bytes)} duplicate bytes for this digest)")

            if len(entries_by_digest) > 1:
                print(f"(x{duplicate_entries_across_digests} = {human_bytes(duplicate_bytes_across_digests)} duplicate bytes for this file size)")
            print()

            DUPLICATE_FILES += duplicate_entries_across_digests

    print(f"TOTAL FILES FOUND: {FILES_FOUND:,}")
    print(f"TOTAL FILES SIZED: {FILES_SIZED:,}")
    print(f"TOTAL FILES SCANNED: {FILES_SCANNED:,}")
    print(f"TOTAL BYTES SCANNED: {BYTES_SCANNED} ({human_bytes(BYTES_SCANNED)})")
    print()
    print(f"TOTAL DUPLICATE FILES: {DUPLICATE_FILES:,} ({safe_percent(DUPLICATE_FILES, FILES_SIZED)} of {FILES_SIZED:,} considered)")
    print(f"TOTAL DUPLICATE BYTES: {DUPLICATE_BYTES} ({human_bytes(DUPLICATE_BYTES)}) ({safe_percent(DUPLICATE_BYTES, BYTES_SCANNED)} of {human_bytes(BYTES_SCANNED)} considered)")


if __name__ == '__main__':
    main()
