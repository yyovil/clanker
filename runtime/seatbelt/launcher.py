"""Reject retired local browser wrappers, including cached profile launchers."""
import sys


def main():
    print("Local browser execution has been removed. Use Clanker's authenticated Kernel browser tools.", file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
