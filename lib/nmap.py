try:
    import re
    import os
    import sys
    import tempfile
    import subprocess
    from lib.core.exceptions import CrowbarExceptions
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))


class Nmap:
    def __init__(self):
        self.nmap_path = "/usr/bin/nmap"
        self.lib = True

        if not os.path.exists(self.nmap_path):
            mess = "File: %s doesn't exists!" % self.nmap_path
            raise CrowbarExceptions(mess)

    def port_scan(self, ip_list, port):
        result = []
        ip = []
        open_port = re.compile("Host:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s\(\)\s+Ports:\s+%s" % port)

        tmpfile = tempfile.NamedTemporaryFile(mode='w+t')
        tmpfile_name = tmpfile.name

        if os.geteuid() != 0:
            nmap_scan_type = "-sT"
        else:
            nmap_scan_type = "-sS"

        nmap_scan_option = "-n -Pn -T4 %s --open -p %s --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=150 -oG %s" % (
            nmap_scan_type, port, tmpfile_name)

        if self.lib:
            nmap_scan_option = "%s %s" % (
                ip_list, nmap_scan_option)
            run_nmap = "%s %s" % (self.nmap_path, nmap_scan_option)
            proc = subprocess.Popen([run_nmap], shell=True, stdout=subprocess.PIPE, )
            stdout_value = str(proc.communicate())
        else:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip_list,
                    arguments=nmap_scan_option)

        try:
            for line in open(tmpfile_name, "r"):
                if re.search(open_port, line):
                    ip = line[:-1].split(" ")[1]
                    result.append(ip)
            return result
        except Exception as err:
            raise CrowbarExceptions(str(err))
