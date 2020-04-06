try:
    import re
    import sys
    import socket
    import struct
    from functools import reduce
    from lib.core.exceptions import CrowbarExceptions
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))


class InvalidIPAddress(ValueError):
    """
    The IP address given to ipaddr is improperly formatted
    """


class IpRange:
    """
    Derived from http://www.randomwalking.com/snippets/iprange.text
    """

    def ipaddr_to_binary(self, ipaddr):
        q = ipaddr.split('.')
        return reduce(lambda a, b: int(a) * 256 + int(b), q)

    def binary_to_ipaddr(self, ipbinary):
        return socket.inet_ntoa(struct.pack('!I', ipbinary))

    def iprange(self, ipaddr):
        span_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The beginning IP address
                             \s*-\s*
                             (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})       # The end IP address
                            ''', re.VERBOSE)
        res = span_re.match(ipaddr)
        if res:
            beginning = res.group(1)
            end = res.group(2)
            return span_iprange(beginning, end)

        cidr_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The IP address
                             /(\d{1,2})                                 # The mask
                          ''', re.VERBOSE)
        res = cidr_re.match(ipaddr)
        if res:
            addr = res.group(1)
            cidrmask = res.group(2)
            return self.cidr_iprange(addr, cidrmask)
        wild_re = re.compile(r'''(\d{1,3}|\*)\.
                             (\d{1,3}|\*)\.
                             (\d{1,3}|\*)\.
                             (\d{1,3}|\*)   # The IP address
                          ''', re.VERBOSE)
        res = wild_re.match(ipaddr)
        if res:
            return wildcard_iprange(ipaddr)

        raise InvalidIPAddress

    def span_iprange(self, beginning, end):
        b = self.ipaddr_to_binary(beginning)
        e = ipaddr_to_binary(end)
        while (b <= e):
            yield binary_to_ipaddr(b)
            b = b + 1

    def cidr_iprange(self, ipaddr, cidrmask):
        mask = (int(2) ** int(32 - int(cidrmask))) - 1
        b = self.ipaddr_to_binary(ipaddr)
        e = self.ipaddr_to_binary(ipaddr)
        b = int(b & ~mask)
        e = int(e | mask)
        while (b <= e):
            yield self.binary_to_ipaddr(b)
            b = b + 1

    def wildcard_iprange(ipaddr):
        beginning = []
        end = []

        tmp = ipaddr.split('.')
        for i in tmp:
            if i == '*':
                beginning.append("0")
                end.append("255")
            else:
                beginning.append(i)
                end.append(i)
        b = beginning[:]
        e = end[:]

        while int(b[0]) <= int(e[0]):
            while int(b[1]) <= int(e[1]):
                while int(b[2]) <= int(e[2]):
                    while int(b[3]) <= int(e[3]):
                        yield b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3]
                        b[3] = "%d" % (int(b[3]) + 1)
                    b[2] = "%d" % (int(b[2]) + 1)
                    b[3] = beginning[3]
                b[1] = "%d" % (int(b[1]) + 1)
                b[2] = beginning[2]
            b[0] = "%d" % (int(b[0]) + 1)
            b[1] = beginning[1]
