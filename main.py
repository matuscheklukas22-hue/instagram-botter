#!/usr/bin/env python3
"""multitool: utilities, Instagram export analysis, and a macOS-friendly memory scanner."""
import argparse
import sys

from tools import insta, memscan, util
from tools.common import ToolError


def build_parser():
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", metavar="<tool>")
    for module in (util, insta, memscan):
        module.register(sub)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return args.func(args) or 0
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
