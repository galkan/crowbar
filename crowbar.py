#!/usr/bin/env python


try:
	from lib.main import Main
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)
     
##
### Main 
##

if __name__ == "__main__":

	crowbar = Main()
	crowbar.run(crowbar.args.brute)
