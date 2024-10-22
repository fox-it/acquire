import ctypes
from ctypes.wintypes import (
    BOOL,
    BYTE,
    DWORD,
    LPVOID,
    LPWSTR,
    PDWORD,
    SHORT,
    ULONG,
    USHORT,
)
from enum import IntEnum
from typing import ClassVar

IF_MAX_PHYS_ADDRESS_LENGTH = 32
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAXLEN_PHYSADDR = 8
MAX_DHCPV6_DUID_LENGTH = 130

NO_ERROR = 0
ERROR_NOT_SUPPORTED = 50
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232

BITNESS = [32, 64][ctypes.sizeof(LPVOID) == 8]


class TCP_TABLE_CLASS(IntEnum):
    BASIC_LISTENER = 0
    BASIC_CONNECTIONS = 1
    BASIC_ALL = 2
    OWNER_PID_LISTENER = 3
    OWNER_PID_CONNECTIONS = 4
    OWNER_PID_ALL = 5
    OWNER_MODULE_LISTENER = 6
    OWNER_MODULE_CONNECTIONS = 7
    OWNER_MODULE_ALL = 8


class UDP_TABLE_CLASS(IntEnum):
    BASIC = 0
    OWNER_PID = 1
    OWNER_MODUL = 2


class MIB_IPNET_TYPE(IntEnum):
    OTHER = 1
    INVALID = 2
    DYNAMIC = 3
    STATIC = 4


class IF_TYPE(IntEnum):
    OTHER = 1
    REGULAR_1822 = 2
    HDH_1822 = 3
    DDN_X25 = 4
    RFC877_X25 = 5
    ETHERNET_CSMACD = 6
    IS088023_CSMACD = 7
    ISO88024_TOKENBUS = 8
    ISO88025_TOKENRING = 9
    ISO88026_MAN = 10
    STARLAN = 11
    PROTEON_10MBIT = 12
    PROTEON_80MBIT = 13
    HYPERCHANNEL = 14
    FDDI = 15
    LAP_B = 16
    SDLC = 17
    DS1 = 18
    E1 = 19
    BASIC_ISDN = 20
    PRIMARY_ISDN = 21
    PROP_POINT2POINT_SERIAL = 22
    PPP = 23
    SOFTWARE_LOOPBACK = 24
    EON = 25
    ETHERNET_3MBIT = 26
    NSIP = 27
    SLIP = 28
    ULTRA = 29
    DS3 = 30
    SIP = 31
    FRAMERELAY = 32
    RS232 = 33
    PARA = 34
    ARCNET = 35
    ARCNET_PLUS = 36
    ATM = 37
    MIO_X25 = 38
    SONET = 39
    X25_PLE = 40
    ISO88022_LLC = 41
    LOCALTALK = 42
    SMDS_DXI = 43
    FRAMERELAY_SERVICE = 44
    V35 = 45
    HSSI = 46
    HIPPI = 47
    MODEM = 48
    AAL5 = 49
    SONET_PATH = 50
    SONET_VT = 51
    SMDS_ICIP = 52
    PROP_VIRTUAL = 53
    PROP_MULTIPLEXOR = 54
    IEEE80212 = 55
    FIBRECHANNEL = 56
    HIPPIINTERFACE = 57
    FRAMERELAY_INTERCONNECT = 58
    AFLANE_8023 = 59
    AFLANE_8025 = 60
    CCTEMUL = 61
    FASTETHER = 62
    ISDN = 63
    V11 = 64
    V36 = 65
    G703_64K = 66
    G703_2MB = 67
    QLLC = 68
    FASTETHER_FX = 69
    CHANNEL = 70
    IEEE80211 = 71
    IBM370PARCHAN = 72
    ESCON = 73
    DLSW = 74
    ISDN_S = 75
    ISDN_U = 76
    LAP_D = 77
    IPSWITCH = 78
    RSRB = 79
    ATM_LOGICAL = 80
    DS0 = 81
    DS0_BUNDLE = 82
    BSC = 83
    ASYNC = 84
    CNR = 85
    ISO88025R_DTR = 86
    EPLRS = 87
    ARAP = 88
    PROP_CNLS = 89
    HOSTPAD = 90
    TERMPAD = 91
    FRAMERELAY_MPI = 92
    X213 = 93
    ADSL = 94
    RADSL = 95
    SDSL = 96
    VDSL = 97
    ISO88025_CRFPRINT = 98
    MYRINET = 99
    VOICE_EM = 100
    VOICE_FXO = 101
    VOICE_FXS = 102
    VOICE_ENCAP = 103
    VOICE_OVERIP = 104
    ATM_DXI = 105
    ATM_FUNI = 106
    ATM_IMA = 107
    PPPMULTILINKBUNDLE = 108
    IPOVER_CDLC = 109
    IPOVER_CLAW = 110
    STACKTOSTACK = 111
    VIRTUALIPADDRESS = 112
    MPC = 113
    IPOVER_ATM = 114
    ISO88025_FIBER = 115
    TDLC = 116
    GIGABITETHERNET = 117
    HDLC = 118
    LAP_F = 119
    V37 = 120
    X25_MLP = 121
    X25_HUNTGROUP = 122
    TRANSPHDLC = 123
    INTERLEAVE = 124
    FAST = 125
    IP = 126
    DOCSCABLE_MACLAYER = 127
    DOCSCABLE_DOWNSTREAM = 128
    DOCSCABLE_UPSTREAM = 129
    A12MPPSWITCH = 130
    TUNNEL = 131
    COFFEE = 132
    CES = 133
    ATM_SUBINTERFACE = 134
    L2_VLAN = 135
    L3_IPVLAN = 136
    L3_IPXVLAN = 137
    DIGITALPOWERLINE = 138
    MEDIAMAILOVERIP = 139
    DTM = 140
    DCN = 141
    IPFORWARD = 142
    MSDSL = 143
    IEEE1394 = 144
    IF_GSN = 145
    DVBRCC_MACLAYER = 146
    DVBRCC_DOWNSTREAM = 147
    DVBRCC_UPSTREAM = 148
    ATM_VIRTUAL = 149
    MPLS_TUNNEL = 150
    SRP = 151
    VOICEOVERATM = 152
    VOICEOVERFRAMERELAY = 153
    IDSL = 154
    COMPOSITELINK = 155
    SS7_SIGLINK = 156
    PROP_WIRELESS_P2P = 157
    FR_FORWARD = 158
    RFC1483 = 159
    USB = 160
    IEEE8023AD_LAG = 161
    BGP_POLICY_ACCOUNTING = 162
    FRF16_MFR_BUNDLE = 163
    H323_GATEKEEPER = 164
    H323_PROXY = 165
    MPLS = 166
    MF_SIGLINK = 167
    HDSL2 = 168
    SHDSL = 169
    DS1_FDL = 170
    POS = 171
    DVB_ASI_IN = 172
    DVB_ASI_OUT = 173
    PLC = 174
    NFAS = 175
    TR008 = 176
    GR303_RDT = 177
    GR303_IDT = 178
    ISUP = 179
    PROP_DOCS_WIRELESS_MACLAYER = 180
    PROP_DOCS_WIRELESS_DOWNSTREAM = 181
    PROP_DOCS_WIRELESS_UPSTREAM = 182
    HIPERLAN2 = 183
    PROP_BWA_P2MP = 184
    SONET_OVERHEAD_CHANNEL = 185
    DIGITAL_WRAPPER_OVERHEAD_CHANNEL = 186
    AAL2 = 187
    RADIO_MAC = 188
    ATM_RADIO = 189
    IMT = 190
    MVL = 191
    REACH_DSL = 192
    FR_DLCI_ENDPT = 193
    ATM_VCI_ENDPT = 194
    OPTICAL_CHANNEL = 195
    OPTICAL_TRANSPORT = 196
    IEEE80216_WMAN = 237
    WWANPP = 243
    WWANPP2 = 244
    IEEE802154 = 259


class ADDRESS_FAMILY(IntEnum):
    AF_UNSPEC = 0
    AF_INET = 2
    AF_INET6 = 23


class NL_NEIGHBOR_STATE(IntEnum):
    UNREACHABLE = 0
    INCOMPLETE = 1
    PROBE = 2
    DELAY = 3
    STALE = 4
    REACHABLE = 5
    PERMANENT = 6
    MAXIMUM = 7


class IF_OPER_STATUS(IntEnum):
    UP = 1
    DOWN = 2
    TESTING = 3
    UNKNOWN = 4
    DORMANT = 5
    NOTPRESENT = 6
    LOWERLAYERDOWN = 7


class NET_IF_CONNECTION_TYPE(IntEnum):
    DEDICATED = 1
    PASSIVE = 2
    DEMAND = 3
    MAXIMUM = 4


class TUNNEL_TYPE(IntEnum):
    TUNNEL_TYPE_NONE = 0
    TUNNEL_TYPE_OTHER = 1
    TUNNEL_TYPE_DIRECT = 2
    TUNNEL_TYPE_6TO4 = 11
    TUNNEL_TYPE_ISATAP = 13
    TUNNEL_TYPE_TEREDO = 14
    TUNNEL_TYPE_IPHTTPS = 15


class TCP_CONNECTION_OFFLOAD_STATE(IntEnum):
    INHOST = 0
    OFFLOADING = 1
    OFFLOADED = 2
    UPLOADING = 3
    MAX = 4


class MIB_TCP_STATE(IntEnum):
    CLOSED = 1
    LISTENING = 2
    SYN_SENT = 3
    SYN_RCVD = 4
    ESTABLISHED = 5
    FIN_WAIT1 = 6
    FIN_WAIT2 = 7
    CLOSE_WAIT = 8
    CLOSING = 9
    LAST_ACK = 10
    TIME_WAIT = 11
    DELETE_TCB = 12
    RESERVED = 100


class CONNECTION_PROTOCOL(IntEnum):
    TCP4 = 1
    UDP4 = 2
    TCP6 = 3
    UDP6 = 4


class IN_ADDR(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("S_addr", ULONG),
    ]


class IN6_ADDR(ctypes.Union):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Byte", BYTE * 16),
        ("Word", USHORT * 8),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sin_family", SHORT),
        ("sin_port", USHORT),
        ("sin_addr", IN_ADDR),
        ("sin_zero", BYTE * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("sin6_family", SHORT),
        ("sin6_port", USHORT),
        ("sin6_flowinfo", ULONG),
        ("sin6_addr", IN6_ADDR),
        ("sin6_scope_id", ULONG),
    ]


class SOCKADDR_INET(ctypes.Union):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", USHORT),
    ]


class MIB_IPNET_ROW2(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Address", SOCKADDR_INET),
        ("InterfaceIndex", ULONG),
        # Padding when executing under 32-bit Python environment here.
        ("InterfaceLuid", LPVOID),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PhysicalAddressLength", ULONG),
        ("State", DWORD),
        ("Flags", BYTE),
        ("ReachabilityTime", ULONG),
    ]

    # 32-bit Python does not correctly align the stucture, which results
    # in no padding being added after the interface index. This causes
    # the size of the object to be 84 instead of the correct 88 bytes.
    # To correct for this, we add an extra four bytes of padding after the
    # `InterfaceIndex` member.
    if BITNESS == 32:
        _fields_.insert(2, ('Padding', DWORD))


class MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("NumEntries", ULONG),
        ("Padding", ULONG),  # Padding to fix alignment
        ("Table", MIB_IPNET_ROW2 * 1),
    ]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Length", ULONG),
        ("Index", ULONG),
        ("Next", LPVOID),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", LPVOID),
        ("FirstAnycastAddress", LPVOID),
        ("FirstMulticastAddress", LPVOID),
        ("FirstDnsServerAddress", LPVOID),
        ("DnsSuffix", LPWSTR),
        ("Description", LPWSTR),
        ("FriendlyName", LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", ULONG),
        ("Flags", ULONG),
        ("Mtu", ULONG),
        ("IfType", ULONG),
        ("OperStatus", DWORD),
        ("Ipv6IfIndex", ULONG),
        ("ZoneIndices", ULONG * 16),
        ("FirstPrefix", LPVOID),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("FirstWinsServerAddress", LPVOID),
        ("FirstGatewayAddress", LPVOID),
        ("Ipv4Metric", ULONG),
        ("Ipv6Metric", ULONG),
        ("Luid", LPVOID),
        ("Dhcpv4Server", BYTE * 16),
        ("CompartmentId", DWORD),
        ("Padding", DWORD),  # Padding to fix alignment
        ("NetworkGuid", BYTE * 16),
        ("ConnectionType", DWORD),
        ("TunnelType", DWORD),
        ("Dhcpv6Server", BYTE * 16),
        ("Dhcpv6ClientDuid", BYTE * MAX_DHCPV6_DUID_LENGTH),
        ("Dhcpv6ClientDuidLength", ULONG),
        ("Dhcpv6Iaid", ULONG),
        ("FirstDnsSuffix", LPVOID),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * 1),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


class MIB_UDP6TABLE_OWNER_PID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("dwNumEntries", DWORD),
        ("table", MIB_UDP6ROW_OWNER_PID * 1),
    ]


PULONG = ctypes.POINTER(ULONG)
PMIB_IPNET_TABLE2 = ctypes.POINTER(MIB_IPNET_TABLE2)
PMIB_TCPTABLE_OWNER_PID = ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)
PMIB_TCP6TABLE_OWNER_PID = ctypes.POINTER(MIB_TCP6TABLE_OWNER_PID)
PMIB_UDPTABLE_OWNER_PID = ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)
PMIB_UDP6TABLE_OWNER_PID = ctypes.POINTER(MIB_UDP6TABLE_OWNER_PID)

iphlpapi = ctypes.WinDLL("Iphlpapi.dll")

# arp calls
GetIpNetTable2 = iphlpapi.GetIpNetTable2
GetIpNetTable2.argtypes = [ULONG, ctypes.POINTER(PMIB_IPNET_TABLE2)]
GetIpNetTable2.restype = ULONG

FreeMibTable = iphlpapi.FreeMibTable
FreeMibTable.argtypes = [LPVOID]
FreeMibTable.restype = None

GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.argtypes = [ULONG, ULONG, LPVOID, LPVOID, PULONG]
GetAdaptersAddresses.restype = ULONG

# net connection calls
GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
GetExtendedTcpTable.argtypes = [LPVOID, PDWORD, BOOL, ULONG, ULONG, ULONG]
GetExtendedTcpTable.restype = DWORD

GetExtendedUdpTable = iphlpapi.GetExtendedUdpTable
GetExtendedUdpTable.argtypes = [LPVOID, PDWORD, BOOL, ULONG, ULONG, ULONG]
GetExtendedUdpTable.restype = DWORD
