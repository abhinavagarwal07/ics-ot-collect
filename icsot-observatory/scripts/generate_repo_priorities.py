#!/usr/bin/env python3
"""Print the initial priority list; never called by runtime or Actions.

Review output separately before replacing the authoritative frozen CSV. This
reproduces the original selection, not later deliberate membership/order edits.
"""
import argparse
import csv
from pathlib import Path
import sys

from icsot_observer.priorities import PRIORITY_FIELDS, initial_priority_rows

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path,
                    default=Path(__file__).resolve().parents[2] / "public_patch_corpus_185.csv")
args = parser.parse_args()
writer = csv.DictWriter(sys.stdout, fieldnames=PRIORITY_FIELDS, lineterminator="\n")
writer.writeheader()
writer.writerows(initial_priority_rows(args.source))
