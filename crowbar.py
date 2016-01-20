#!/usr/bin/env python2

try:
    from lib.main import Main
    from lib.core.exceptions import CrowbarExceptions
except Exception, err:
        import sys
        print >> sys.stderr, err
        sys.exit(1)

##
### Main
##

if __name__ == "__main__":

    try:
        crowbar = Main()
        crowbar.run(crowbar.args.brute)
    except Exception, err:
        import sys
        print >> sys.stderr, err
        sys.exit(1)
