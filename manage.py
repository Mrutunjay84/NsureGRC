#!/usr/bin/env python
import os
import sys


def main() -> None:
    # Safe default: production settings (which refuse to start insecurely). Developers pick dev explicitly.
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
