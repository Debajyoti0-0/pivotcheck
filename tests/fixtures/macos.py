"""Deterministic macOS command-output fixtures.

Representative, sanitized outputs modeled on real macOS (Ventura/Sonoma)
command behavior. Used by parser and collector contract tests.
"""

IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x10
\tnd6 options=201<PERFORMNUD,DAD>
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6403<RXCSUM,TXCSUM,CHANNEL_IO,PARTIAL_CSUM,ZEROINTEL_CSUM>
\tether a4:83:e7:aa:bb:cc
\tinet 10.0.0.5 netmask 0xffffff00 broadcast 10.0.0.255
\tinet6 fe80::14c2:1d3f:5b21:9a2c%en0 prefixlen 64 secured scopeid 0x6
\tinet6 2601:646:9e00:1f90:1234:5678:9abc:def0 prefixlen 64 autoconf secured
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
en1: flags=8802<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\toptions=50<TSO4,TSO6>
\tether ac:de:48:00:11:22
\tmedia: none
\tstatus: inactive
utun3: flags=8051<UP,POINTOPOINT,RUNNING,NONSLEEPING,MULTICAST> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
"""

NETSTAT_RN = """\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.0.0.1           UGScg                 en0
10.0.0/24          link#5             UCS                   en0      !
10.0.0.1/32        link#5             UHmwI                 lo0
10.0.0.5/32        link#5             UH                    en0
127                127.0.0.1           UCS                  lo0
127.0.0.1/32       link#1             UH                    lo0
10.8.0.1/32        10.8.0.2           UH                    utun3

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGcg          en0
::1                                     ::1                             UHL           lo0
fe80::/64                               link#5                          UCS           en0
2601:646:9e00:1f90::/64                 link#5                          UC            en0
"""

ARP_A = """\
? (10.0.0.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
? (10.0.0.25) at 0:1b:44:11:3a:b7 on en0 ifscope [ethernet]
? (10.0.0.99) at (incomplete) on en0 ifscope [ethernet]
? (10.8.0.1) at 10.8.0.1 on utun3
? (10.0.0.5) at a4:83:e7:aa:bb:cc on en0 ifscope permanent [ethernet]
"""

SCUTIL_DNS = """\
DNS configuration

resolver #1
  nameserver[0] : 10.0.0.1
  nameserver[1] : 10.0.0.53
  if_index : 6 (en0)
  flags    : Supplemental, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  nameserver[0] : 10.0.0.1
  if_index : 6 (en0)
  flags    : Supplemental, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 10.0.0.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  search domain[0] : lan
"""

NETSTAT_AN = """\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  10.0.0.5.631           *.*                    LISTEN
tcp4       0      0  127.0.0.1.49153        127.0.0.1.49152        ESTABLISHED
tcp6       0      0  ::1.49153              ::1.49152              ESTABLISHED
tcp4       0      0  *.22                   *.*                    LISTEN
udp4       0      0  10.0.0.5.5353          *.*
udp6       0      0  *.546                  *.*
"""
