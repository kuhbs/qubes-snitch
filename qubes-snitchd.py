#!/usr/bin/env python3
#
# Qubes Snitch daemon entrypoint
# Runtime code lives in qubes_snitch.daemon_runtime so this executable stays readable

from qubes_snitch.daemon_runtime import main


if __name__ == "__main__":
    main()
