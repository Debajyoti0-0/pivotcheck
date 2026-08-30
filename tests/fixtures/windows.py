"""Deterministic Windows command-output fixtures.

Representative, sanitized outputs modeled on real Windows 10/11 command
behavior (English locale). Used by parser and collector contract tests.
"""

IPCONFIG_ALL = """\

Windows IP Configuration

  Host Name . . . . . . . . . . . . : DESKTOP-WKS01
  Primary Dns Suffix  . . . . . . . :
  Node Type . . . . . . . . . . . . : Hybrid
  IP Routing Enabled. . . . . . . . : No
  WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : corp.example.invalid
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 3C-97-0E-12-34-56
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 10.10.20.15(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Monday, January 1, 2024 08:00:00
   Lease Expires . . . . . . . . . . : Tuesday, January 2, 2024 08:00:00
   Default Gateway . . . . . . . . . : 10.10.20.254
   DHCP Server . . . . . . . . . . . : 10.10.20.1
   DNS Servers . . . . . . . . . . . : 10.10.20.1
                                         10.10.20.53
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Realtek USB GbE Family Controller
   Physical Address. . . . . . . . . : 48-2A-E3-AB-CD-EF
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   Physical Address. . . . . . . . . : 7C-B5-9B-11-22-33
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.100.5(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.1
   DNS Servers . . . . . . . . . . . : 192.168.100.1
   NetBIOS over Tcpip. . . . . . . . : Disabled
"""

ROUTE_PRINT = """\

===========================================================================
Interface List
 12...3c 97 0e 12 34 56 ......Intel(R) Ethernet Connection
  7...48 2a e3 ab cd ef ......Realtek USB GbE Family Controller
  5...7c b5 9b 11 22 33 ......Intel(R) Wi-Fi 6 AX201
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.10.20.254      10.10.20.15     25
         10.10.20.0    255.255.255.0         On-link         10.10.20.15    281
     10.10.20.15  255.255.255.255         On-link         10.10.20.15    281
     10.10.20.255  255.255.255.255         On-link         10.10.20.15    281
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
      192.168.100.0    255.255.255.0         On-link       192.168.100.5    291
      192.168.100.5  255.255.255.255         On-link       192.168.100.5    291
    192.168.100.255  255.255.255.255         On-link       192.168.100.5    291
===========================================================================
Persistent Routes:
  None

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
 12    281 fe80::/64                On-link
 12    281 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
"""

ARP_A = """\

Interface: 10.10.20.15 --- 0xc
  Internet Address      Physical Address      Type
  10.10.20.1            a4-2b-b0-aa-bb-cc     dynamic
  10.10.20.25           00-1b-44-11-3a-b7     static
  10.10.20.254          a4-2b-b0-dd-ee-ff     dynamic

Interface: 192.168.100.5 --- 0x5
  Internet Address      Physical Address      Type
  192.168.100.1         11-22-33-44-55-66     dynamic
  192.168.100.255       ff-ff-ff-ff-ff-ff     invalid
"""

NETSTAT_ANO = """\

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1124
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    10.10.20.15:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.20.15:52108      140.82.114.23:443      ESTABLISHED     1890
  TCP    [::]:135               [::]:0                 LISTENING       1124
  UDP    0.0.0.0:5353           *:*                                    4812
  UDP    [::]:500               *:*                                    1124
"""

TASKLIST_CSV = """\
"System",4,"Services",0,"8,192","N/A"
"svchost.exe",1124,"Services",0,"45,388","N/A"
"firefox.exe",1890,"Console",1,"812,396","N/A"
"mDNSResponder.exe",4812,"Services",0,"9,240","N/A"
"""
