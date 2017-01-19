#!/usr/local/bin/python3

"""
This script identifies all duplicate copies of files across the system.

<3 Matt
"""

import collections
import os
import pathlib
import subprocess
import sys


HOME = pathlib.Path("~").expanduser() / "Documents"
assert HOME.exists()

DUPLICATES = 0
TOTAL = 0


def calc_md5(filepath):
    return subprocess.check_output(["md5", filepath]).split(b' ')[-1].strip()


def calc_size(filepath):
    return int(subprocess.check_output(["ls", "-l", filepath]).split()[4])


def yield_filepaths(path):
    global TOTAL

    gen = os.walk(path)
    for (path, directories, filenames) in gen:
        for directory in directories:
            if directory.startswith('.'):
                directories.remove(directory)

        for filename in [f for f in filenames if not f.startswith('.')]:
            filepath = pathlib.Path(path) / filename

            if filepath.is_symlink():
                continue
            elif str(filepath).endswith("__init__.py"):
                continue
            elif str(filepath).endswith(".pyc"):
                continue

            TOTAL += 1
            sys.stdout.write("{} files found\r".format(TOTAL))
            yield filepath


def group_matches_by(filepaths, func):
    groups = collections.defaultdict(list)
    for filepath in filepaths:
        group = func(filepath)
        groups[group].append(filepath)

    for (key, val) in list(groups.items()):
        if len(val) == 1:
            del groups[key]

    return groups


def main():
    global DUPLICATES
    global TOTAL

    filepaths = yield_filepaths(HOME)

    sizes = group_matches_by(filepaths, calc_size)
    del sizes[0]

    print("\n\n")
    for (size, filepaths) in list(sizes.items()):
        hashes = group_matches_by(filepaths, calc_md5)
        if hashes:
            print("{}".format(size))
            for (md5, filepaths) in list(hashes.items()):
                print("  {}".format(md5))
                for filepath in filepaths:
                    print("    {}".format(filepath))
                print()


if __name__ == '__main__':
    main()
