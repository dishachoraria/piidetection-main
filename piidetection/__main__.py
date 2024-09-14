#!/usr/bin/env python
"""The main entry point. Invoke as `piidetection' or `python -m piidetection`.

"""
import sys


def main():
    try:
        from .core import app

        exit_status = app()
    except KeyboardInterrupt:
        print("Ctrl-C pressed. Aborting")
    sys.exit(0)


if __name__ == "__main__":
    main()
