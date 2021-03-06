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


DUPLICATES = 0
TOTAL = 0
TOTAL_BYTES = 0
DUPLICATE_BYTES = 0

SIZE_MIN = 1 * 1024 * 1024


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

    for entry in os.scandir(path):
        if entry.name.startswith('.'):
            continue

        if entry.is_symlink():
            continue

        elif entry.is_dir():
            yield from scantree(entry.path)
        else:
            yield entry


def yield_entries(path):
    global TOTAL

    gen = scantree(path)
    for entry in gen:

        filename = entry.name
        if filename.startswith('.'):
            continue

        # elif str(filepath).endswith("__init__.py"):
        #     continue
        # elif str(filepath).endswith(".pyc"):
        #     continue

        TOTAL += 1
        if not TOTAL % 100:
            sys.stdout.write(f"{TOTAL} files found\r")
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
    global DUPLICATES
    global TOTAL
    global TOTAL_BYTES
    global DUPLICATE_BYTES

    path = get_path()

    all_entries = yield_entries(path)

    sizes = group_matches_by(all_entries, lambda e: e.stat().st_size)
    if 0 in sizes:
        del sizes[0]

    print("\n\n")
    for (size, entries_by_size) in sorted(sizes.items()):
        if size < SIZE_MIN:
            continue

        entries_by_hash = group_matches_by(entries_by_size, fast_hash)
        if entries_by_hash:
            print(f"{size} ({human_bytes(size)})")
            for (hash, entries) in entries_by_hash.items():
                TOTAL_BYTES += size * len(entries)
                DUPLICATE_BYTES += size * (len(entries) - 1)
                print(f"  {hash}")
                for entry in entries:
                    print(f"    {entry.path}")
                print()

    print(f"TOTAL FILES VISITED: {TOTAL:,}")
    print(f"TOTAL BYTES HASHED: {TOTAL_BYTES} ({human_bytes(TOTAL_BYTES)})")
    print(f"TOTAL DUPLICATE BYTES: {DUPLICATE_BYTES} ({human_bytes(DUPLICATE_BYTES)})")


if __name__ == '__main__':
    main()
