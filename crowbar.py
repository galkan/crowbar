#!/usr/bin/env python3

try:
    from lib.main import Main
    from lib.core.exceptions import CrowbarExceptions
except Exception as err:
    import sys
    print(err, file=sys.stderr)
    sys.exit(1)

##
### Main
##

if __name__ == "__main__":

    try:
        crowbar = Main()
        crowbar.run(crowbar.args.brute)
    except Exception as err:
        import sys
        print(err, file=sys.stderr)
        sys.exit(1)
