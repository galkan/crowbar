try:
    import os
    import re
    import sys
    import shlex
    import signal
    import paramiko
    import argparse
    import tempfile
    import subprocess
    from lib.nmap import Nmap
    from lib.core.common import *
    from lib.core.logger import Logger
    from lib.core.threadpool import ThreadPool
    from lib.core.exceptions import CrowbarExceptions
    from lib.core.iprange import IpRange, InvalidIPAddress
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))

__version__ = '0.4.3-dev'
__banner__ = 'Crowbar v%s' % (__version__)

def main():
    try:
        crowbar = Main()
        crowbar.run(crowbar.args.brute)
    except Exception as err:
        import sys

        print(err, file=sys.stderr)
        sys.exit(1)

class AddressAction(argparse.Action):
    def __call__(self, parser, args, values, option=None):

        if args.username:
            if len(args.username) > 1:
                args.username = "\"" + ' '.join([str(line) for line in args.username]) + "\""
            else:
                args.username = args.username[0]

            warning = {args.username: "-U", args.passwd: "-C", args.server: "-S"}
            for _ in warning.keys():
                if _ and os.path.isfile(_):
                    mess = "%s is not a valid option. Please use %s option" % (_, warning[_])
                    raise CrowbarExceptions(mess)

        if args.brute == "sshkey":
            if args.key_file is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -k/--key: expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "rdp":
            if (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.passwd is None) and (args.passwd_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -c/--passwd or -C/--passwdfile expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "vnckey":
            if args.key_file is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -k/--key: expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "openvpn":
            if args.config is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -m/--config expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.passwd is None) and (args.passwd_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -c/--passwd or -C/--passwdfile expected one argument """
                raise CrowbarExceptions(mess)


class Main:
    is_success = 0

    def __init__(self):
        self.services = {"openvpn": self.openvpn, "rdp": self.rdp, "sshkey": self.sshkey, "vnckey": self.vnckey}
        self.crowbar_readme = "https://github.com/galkan/crowbar/blob/master/README.md"

        self.openvpn_path = "/usr/sbin/openvpn"
        self.vpn_failure = re.compile("SIGTERM\[soft,auth-failure\] received, process exiting")
        self.vpn_success = re.compile("Initialization Sequence Completed")
        self.vpn_remote_regex = re.compile("^\s+remote\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}")
        self.vpn_warning = "Warning! Both \"remote\" options were used at the same time. But command line \"remote\" options will be used!"
        self.vpn_error_in_use = "Address already in use (errno=98)"

        self.xfreerdp_path = "/usr/bin/xfreerdp"
        self.rdp_success = "Authentication only, exit status 0"
        self.rdp_success_ins_priv = "insufficient access privileges"
        self.rdp_success_account_locked = "alert internal error"
        self.rdp_error_host_down = "ERRCONNECT_CONNECT_FAILED"  # [0x00020006] [0x00020014]
        self.rdp_error_display = "Please check that the \$DISPLAY environment variable is properly set."

        self.vncviewer_path = "/usr/bin/vncviewer"
        self.vnc_success = "Authentication successful"

        description = "Crowbar is a brute force tool which supports OpenVPN, Remote Desktop Protocol, SSH Private Keys and VNC Keys."
        usage = "Usage: use --help for further information"

        parser = argparse.ArgumentParser(description=description, usage=usage)
        parser.add_argument('-b', '--brute', dest='brute', help='Target service', choices=self.services.keys(),
                            required=True)
        parser.add_argument('-s', '--server', dest='server', action='store', help='Static target')
        parser.add_argument('-S', '--serverfile', dest='server_file', action='store',
                            help='Multiple targets stored in a file')
        parser.add_argument('-u', '--username', dest='username', action='store', nargs='+',
                            help='Static name to login with')
        parser.add_argument('-U', '--usernamefile', dest='username_file', action='store',
                            help='Multiple names to login with, stored in a file')
        parser.add_argument('-n', '--number', dest='thread', action='store',
                            help='Number of threads to be active at once', default=5, type=int)
        parser.add_argument('-l', '--log', dest='log_file', action='store', help='Log file (only write attempts)',
                            metavar='FILE',
                            default="crowbar.log")
        parser.add_argument('-o', '--output', dest='output', action='store', help='Output file (write everything else)',
                            metavar='FILE',
                            default="crowbar.out")
        parser.add_argument('-c', '--passwd', dest='passwd', action='store', help='Static password to login with')
        parser.add_argument('-C', '--passwdfile', dest='passwd_file', action='store',
                            help='Multiple passwords to login with, stored in a file',
                            metavar='FILE')
        parser.add_argument('-t', '--timeout', dest='timeout', action='store',
                            help='[SSH] How long to wait for each thread (seconds)', default=10, type=int)
        parser.add_argument('-p', '--port', dest='port', action='store',
                            help='Alter the port if the service is not using the default value', type=int)
        parser.add_argument('-k', '--keyfile', dest='key_file', action='store',
                            help='[SSH/VNC] (Private) Key file or folder containing multiple files')
        parser.add_argument('-m', '--config', dest='config', action='store', help='[OpenVPN] Configuration file ')
        parser.add_argument('-d', '--discover', dest='discover', action='store_true',
                            help='Port scan before attacking open ports', default=False)
        parser.add_argument('-v', '--verbose', dest='verbose', action="count",
                            help='Enable verbose output (-vv for more)', default=False)
        parser.add_argument('-D', '--debug', dest='debug', action='store_true', help='Enable debug mode', default=False)
        parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='Only display successful logins',
                            default=False)
        parser.add_argument('options', nargs='*', action=AddressAction)

        try:
            self.args = parser.parse_args()
        except Exception as err:
            raise CrowbarExceptions(str(err))

        self.ip_list = []

        if self.args.discover:
            self.nmap = Nmap()
        else:
            iprange = IpRange()

            try:
                if self.args.server is not None:
                    for _ in self.args.server.split(","):
                        for ip in iprange.iprange(_):
                            self.ip_list.append(ip)
                else:
                    for _ in open(self.args.server_file, "r"):
                        for ip in iprange.iprange(_):
                            if not ip in self.ip_list:
                                self.ip_list.append(ip)
            except IOError:
                mess = "File: %s cannot be opened" % os.path.abspath(self.args.server_file)
                raise CrowbarExceptions(mess)
            except:
                mess = "Invalid IP Address! Please use IP/CIDR notation <192.168.37.37/32, 192.168.1.0/24>"
                raise CrowbarExceptions(mess)

        if self.args.verbose:
            self.logger = Logger(self.args.log_file, self.args.output, True)
        else:
            self.logger = Logger(self.args.log_file, self.args.output)

        self.logger.output_file("START")
        if not self.args.quiet:
            self.logger.output_file(__banner__)

        if self.args.verbose:
            self.logger.output_file("Brute Force Type: %s" % self.args.brute)
            self.logger.output_file("     Output File: %s" % os.path.abspath(self.args.output))
            self.logger.output_file("        Log File: %s" % os.path.abspath(self.args.log_file))
            self.logger.output_file("   Discover Mode: %s" % self.args.discover)
            self.logger.output_file("    Verbose Mode: %s" % self.args.verbose)
            self.logger.output_file("      Debug Mode: %s" % self.args.debug)

    def openvpnlogin(self, ip, username, password, brute_file, port):
        brute_file_name = brute_file.name
        brute_file.seek(0)

        openvpn_cmd = "%s --remote %s %s --auth-user-pass %s --tls-exit --connect-retry-max 0 --config %s" % (
            self.openvpn_path, ip, port, brute_file_name, self.args.config)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % openvpn_cmd)

        proc = subprocess.Popen(shlex.split(openvpn_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-OPENVPN: " + ip + ":" + str(port) + " - " + username + ":" + password + " - " + brute_file_name
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            # Success
            if re.search(self.vpn_success, str(line)):
                result = bcolors.OKGREEN + "OPENVPN-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + username + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                os.kill(proc.pid, signal.SIGQUIT)
            # Errors
            elif re.search(self.vpn_error_in_use, str(line)):
                mess = "Already connected to a VPN"
                raise CrowbarExceptions(mess)
        brute_file.close()

    def openvpn(self):
        port = 443  # TCP 443, TCP 943, UDP 1194

        if not 'SUDO_UID' in os.environ.keys():
            mess = "OpenVPN requires super user privileges"
            raise CrowbarExceptions(mess)

        if not os.path.exists(self.openvpn_path):
            mess = "openvpn: %s path doesn't exists on the system" % os.path.abspath(self.openvpn_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        for config_line in open(self.args.config, "r"):
            if re.search(self.vpn_remote_regex, config_line):
                raise CrowbarExceptions(self.vpn_warning)

        if self.args.username_file:
            if not os.path.exists(self.args.username_file):
                mess = "File: %s doesn't exists ~ %s" % os.path.abspath(self.args.username_file)
                raise CrowbarExceptions(mess)

        if self.args.passwd_file:
            if not os.path.exists(self.args.passwd_file):
                mess = "File: %s doesn't exists ~ %s" % os.path.abspath(self.args.passwd_file)
                raise CrowbarExceptions(mess)

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except Exception as err:
                    mess = "Error: %s" % err
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if self.args.passwd_file:
                        try:
                            passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                        except Exception as err:
                            mess = "Error: %s" % err
                            raise CrowbarExceptions(mess)

                        for password in passwdfile:
                            brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                            brute_file.write(user + "\n")
                            brute_file.write(password + "\n")
                            pool.add_task(self.openvpnlogin, ip, user, password, brute_file, port)
                    else:
                        brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                        brute_file.write(user + "\n")
                        brute_file.write(self.args.passwd + "\n")
                        pool.add_task(self.openvpnlogin, ip, user, self.args.passwd, brute_file, port)
            else:
                if self.args.passwd_file:
                    try:
                        passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                    except Exception as err:
                        mess = "Error: %s" % err
                        raise CrowbarExceptions(mess)

                    for password in passwdfile:
                        brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                        brute_file.write(self.args.username + "\n")
                        brute_file.write(password + "\n")
                        pool.add_task(self.openvpnlogin, ip, self.args.username, password, brute_file, port)
                else:
                    brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                    brute_file.write(self.args.username + "\n")
                    brute_file.write(self.args.passwd + "\n")
                    pool.add_task(self.openvpnlogin, ip, self.args.username, self.args.passwd, brute_file, port)
        pool.wait_completion()

    def vnclogin(self, ip, port, keyfile):
        vnc_cmd = "%s -passwd %s %s:%s" % (self.vncviewer_path, keyfile, ip, port)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % vnc_cmd)

        proc = subprocess.Popen(shlex.split(vnc_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-VNC: " + ip + ":" + str(port) + " - " + keyfile
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            if re.search(self.vnc_success, str(line)):
                os.kill(proc.pid, signal.SIGQUIT)
                result = bcolors.OKGREEN + "VNC-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + keyfile + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break

    def vnckey(self, *options):
        port = 5901

        if not os.path.exists(self.vncviewer_path):
            mess = "vncviewer: %s path doesn't exists on the system" % os.path.abspath(self.vncviewer_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        if not os.path.isfile(self.args.key_file):
            mess = "Key file: \"%s\" doesn't exists" % os.path.abspath(self.args.key_file)
            raise CrowbarExceptions(mess)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))
            pool.add_task(self.vnclogin, ip, port, self.args.key_file)
        pool.wait_completion()

    def rdplogin(self, ip, user, password, port):
        # Could look into using: -grab-keyboard -mouse-motion -wallpaper -themes
        rdp_cmd = "%s /v:%s /port:%s /u:%s /p:%s /cert-ignore -clipboard +auth-only " % (
            self.xfreerdp_path, ip, port, user, password)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % rdp_cmd)

        # stderr to stdout
        proc = subprocess.Popen(shlex.split(rdp_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-RDP: " + ip + ":" + str(port) + " - " + user + ":" + password
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            # Success
            if re.search(self.rdp_success, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            elif re.search(self.rdp_success_ins_priv, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS (INSUFFICIENT PRIVILEGES) : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            elif re.search(self.rdp_success_account_locked, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS (ACCOUNT_LOCKED_OR_PASSWORD_EXPIRED) : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            # Errors
            elif re.search(self.rdp_error_display, str(line)):
                mess = "Please check \$DISPLAY is properly set. See README.md %s" % self.crowbar_readme
                raise CrowbarExceptions(mess)
            elif re.search(self.rdp_error_host_down, str(line)):
                mess = "Host isn't up"
                raise CrowbarExceptions(mess)

    def rdp(self):
        port = 3389

        if not os.path.exists(self.xfreerdp_path):
            mess = "xfreerdp: %s path doesn't exists on the system" % os.path.abspath(self.xfreerdp_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        if self.args.username_file:
            if not os.path.exists(self.args.username_file):
                mess = "File: %s doesn't exists ~ %s" % os.path.abspath(self.args.username_file)
                raise CrowbarExceptions(mess)

        if self.args.passwd_file:
            if not os.path.exists(self.args.passwd_file):
                mess = "File: %s doesn't exists ~ %s" % os.path.abspath(self.args.passwd_file)
                raise CrowbarExceptions(mess)

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except Exception as err:
                    mess = "Error: %s" % err
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if ' ' in user:
                        user = '"' + user + '"'

                    if self.args.passwd_file:
                        try:
                            passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                        except Exception as err:
                            mess = "Error: %s" % err
                            raise CrowbarExceptions(mess)

                        for password in passwdfile:
                            pool.add_task(self.rdplogin, ip, user, password, port)
                    else:
                        pool.add_task(self.rdplogin, ip, user, self.args.passwd, port)
            else:
                if self.args.passwd_file:
                    try:
                        passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                    except Exception as err:
                        mess = "Error: %s" % err
                        raise CrowbarExceptions(mess)

                    for password in passwdfile:
                        pool.add_task(self.rdplogin, ip, self.args.username, password, port)
                else:
                    pool.add_task(self.rdplogin, ip, self.args.username, self.args.passwd, port)
        pool.wait_completion()

    def sshlogin(self, ip, port, user, keyfile, timeout):
        try:
            ssh = paramiko.SSHClient()
            paramiko.util.log_to_file("/dev/null")
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except:
            pass
        else:
            brute = "LOG-SSH: " + ip + ":" + str(port) + " - " + user + ":" + keyfile + ":" + str(timeout)
            self.logger.log_file(brute)

            try:
                ssh.connect(ip, port, username=user, password=None, pkey=None, key_filename=keyfile, timeout=timeout,
                            allow_agent=False, look_for_keys=False)
                result = bcolors.OKGREEN + "SSH-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + keyfile + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
            except:
                pass

    def sshkey(self):
        port = 22

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(self.args.thread)
        except Exception as err:
            raise CrowbarExceptions(str(err))

        if self.args.username_file:
            if not os.path.exists(self.args.username_file):
                mess = "File: %s doesn't exists ~ %s" % os.path.abspath(self.args.username_file)
                raise CrowbarExceptions(mess)

        if not os.path.exists(self.args.key_file):
            mess = "Key file/folder: \"%s\" doesn't exists" % os.path.abspath(self.args.key_file)
            raise CrowbarExceptions(mess)

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except Exception as err:
                    mess = "Error: %s" % err
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if os.path.isdir(self.args.key_file):
                        for dirname, dirnames, filenames in os.walk(self.args.key_file):
                            for keyfile in filenames:
                                keyfile_path = self.args.key_file + "/" + keyfile
                                if keyfile.endswith('.pub', 4):
                                    self.logger.output_file("LOG-SSH: Skipping Public Key - %s" % keyfile_path)
                                    continue
                                pool.add_task(self.sshlogin, ip, port, user, keyfile_path, self.args.timeout)
                    else:
                        pool.add_task(self.sshlogin, ip, port, user, self.args.key_file, self.args.timeout)
            else:
                if os.path.isdir(self.args.key_file):
                    for dirname, dirnames, filenames in os.walk(self.args.key_file):
                        for keyfile in filenames:
                            keyfile_path = dirname + "/" + keyfile
                            if keyfile.endswith('.pub', 4):
                                self.logger.output_file("LOG-SSH: Skipping Public Key - %s" % keyfile_path)
                                continue
                            pool.add_task(self.sshlogin, ip, port, self.args.username, keyfile_path, self.args.timeout)
                else:
                    pool.add_task(self.sshlogin, ip, port, self.args.username, self.args.key_file, self.args.timeout)
        pool.wait_completion()

    def run(self, brute_type):
        signal.signal(signal.SIGINT, self.signal_handler)

        if not brute_type in self.services.keys():
            mess = "%s is not a valid service. Please select: %s" % (brute_type, self.services.keys())
            raise CrowbarExceptions(mess)
        else:
            self.services[brute_type]()
            self.logger.output_file("STOP")

            if Main.is_success == 0:
                self.logger.output_file("No results found...")

    def signal_handler(self, signal, frame):
        raise CrowbarExceptions("\nExiting...")
