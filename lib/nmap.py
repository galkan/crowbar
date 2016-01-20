try:
    import re
    import os
    import sys
    import tempfile
    import subprocess
    from lib.core.exceptions import CrowbarExceptions
except Exception, err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))

class Nmap:
    def __init__(self):
        self.nmap_path = "/usr/bin/nmap"
        self.lib = True

        if not os.path.exists(self.nmap_path):
            try:
                import nmap
                self.lib = False
            except ImportError:
                mess = "Please install the pyhon-nmap module (pip install nmap)!"
                raise CrowbarExceptions(mess)
            except:
                mess = "File: %s doesn't exists!" % self.nmap_path
                raise CrowbarExceptions(mess)

    def port_scan(self, ip_list, port):
        result = []
        ip = []
        open_port = re.compile("Host:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s\(\)\s+Ports:\s+%s" % port)

        tmpfile = tempfile.NamedTemporaryFile(mode='w+t')
        tmpfile_name = tmpfile.name

        if self.lib:
            nmap_scan_option = "-n -Pn -T4 -sS %s --open -p %s --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=150 -oG %s" % (
                ip_list, port, tmpfile_name)
            run_nmap = "%s %s" % (self.nmap_path, nmap_scan_option)
            proc = subprocess.Popen([run_nmap], shell=True, stdout=subprocess.PIPE, )
            stdout_value = str(proc.communicate())
        else:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip_list,
                    arguments="-n -Pn -T4 -sS --open -p %s --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=150 -oG %s" % (
                        port, tmpfile_name))

        try:
            for line in open(tmpfile_name, "r"):
                if re.search(open_port, line):
                    ip = line[:-1].split(" ")[1]
                    result.append(ip)
            return result
        except Exception, err:
            raise CrowbarExceptions(str(err))
