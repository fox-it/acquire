from __future__ import annotations

import ctypes
from json import dumps
from socket import htons, inet_ntop
from typing import Callable, Union

from acquire.dynamic.windows.iphlpapi import (
    ADDRESS_FAMILY,
    BOOL,
    CONNECTION_PROTOCOL,
    ERROR_INSUFFICIENT_BUFFER,
    LPVOID,
    MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID,
    MIB_TCP_STATE,
    MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID,
    MIB_UDPTABLE_OWNER_PID,
    NO_ERROR,
    PDWORD,
    TCP_CONNECTION_OFFLOAD_STATE,
    TCP_TABLE_CLASS,
    UDP_TABLE_CLASS,
    ULONG,
    GetExtendedTcpTable,
    GetExtendedUdpTable,
)

NetConnTableClass = Union[TCP_TABLE_CLASS, UDP_TABLE_CLASS]
NetConnTableType = Union[
    MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID
]
NetConnTableRowType = Union[MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID]
NetConnTableResult = Union[
    MIB_TCPTABLE_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, MIB_UDP6TABLE_OWNER_PID
]
NetConnTableCallback = Callable[[LPVOID, PDWORD, BOOL, ULONG, ULONG, ULONG], NetConnTableResult]

NetConnRowParserArgs = Union[MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID]
NetConnRowParser = Callable[[NetConnRowParserArgs], "NetConnection"]


class NetConnection:
    def __init__(
        self,
        protocol: CONNECTION_PROTOCOL,
        local_addr: str,
        local_port: int,
        remote_addr: str | None,
        remote_port: int | None,
        state: TCP_CONNECTION_OFFLOAD_STATE | None,
        pid: int,
    ) -> None:
        self.protocol = protocol
        self.local_address = local_addr
        self.local_port = local_port
        self.remote_address = remote_addr
        self.remote_port = remote_port
        self.state = state
        self.pid = pid

    def as_dict(self) -> dict:
        return {
            "protocol": self.protocol.name,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state.name if self.state else None,
            "pid": self.pid,
        }

    def __str__(self) -> str:
        state = self.state.name if self.state else None
        return (
            f"NetConnection(protocol={self.protocol.name}, lhost={self.local_address}, lport={self.local_port}, "
            f"rhost={self.remote_address}, rport={self.remote_port}, state={state}, pid={self.pid})"
        )


def get_netconn_table(
    get_netconn_table_proc: NetConnTableCallback,
    family: ADDRESS_FAMILY,
    cls: NetConnTableClass,
    table_type: NetConnTableType,
) -> NetConnTableResult | None:
    table_size = ULONG(0)
    result = get_netconn_table_proc(LPVOID(0), ctypes.byref(table_size), True, family, cls, ULONG(0))

    if result != ERROR_INSUFFICIENT_BUFFER:
        return None

    buffer = ctypes.create_string_buffer(table_size.value)
    result = get_netconn_table_proc(buffer, ctypes.byref(table_size), True, family, cls, ULONG(0))

    if result != NO_ERROR:
        return None

    return ctypes.cast(buffer, ctypes.POINTER(table_type)).contents


def parse_netconn_rows(
    table: NetConnTableType, row_type: NetConnTableRowType, row_parse_callback: NetConnRowParser
) -> list[NetConnection]:
    entries = table.dwNumEntries
    rows = ctypes.cast(table.table, ctypes.POINTER(row_type * entries)).contents

    connections = []

    for row in rows:
        conn = row_parse_callback(row)
        connections.append(conn)

    return connections


def tcp4_row_parser(row: MIB_TCPROW_OWNER_PID) -> NetConnection:
    return NetConnection(
        protocol=CONNECTION_PROTOCOL.TCP4,
        local_addr=inet_ntop(ADDRESS_FAMILY.AF_INET, row.dwLocalAddr.to_bytes(4, byteorder="little")),
        local_port=htons(row.dwLocalPort),
        remote_addr=inet_ntop(ADDRESS_FAMILY.AF_INET, row.dwRemoteAddr.to_bytes(4, byteorder="little")),
        remote_port=htons(row.dwRemotePort),
        state=MIB_TCP_STATE(row.dwState),
        pid=row.dwOwningPid,
    )


def udp4_row_parser(row: MIB_UDPROW_OWNER_PID) -> NetConnection:
    return NetConnection(
        protocol=CONNECTION_PROTOCOL.UDP4,
        local_addr=inet_ntop(ADDRESS_FAMILY.AF_INET, row.dwLocalAddr.to_bytes(4, byteorder="little")),
        local_port=htons(row.dwLocalPort),
        remote_addr=None,
        remote_port=None,
        state=None,
        pid=row.dwOwningPid,
    )


def tcp6_row_parser(row: MIB_TCP6ROW_OWNER_PID) -> NetConnection:
    return NetConnection(
        protocol=CONNECTION_PROTOCOL.TCP6,
        local_addr=f"[{inet_ntop(ADDRESS_FAMILY.AF_INET6, row.ucLocalAddr)}]",
        local_port=htons(row.dwLocalPort),
        remote_addr=f"[{inet_ntop(ADDRESS_FAMILY.AF_INET6, row.ucRemoteAddr)}]",
        remote_port=htons(row.dwRemotePort),
        state=MIB_TCP_STATE(row.dwState),
        pid=row.dwOwningPid,
    )


def udp6_row_parser(row: MIB_UDP6ROW_OWNER_PID) -> NetConnection:
    return NetConnection(
        protocol=CONNECTION_PROTOCOL.UDP6,
        local_addr=f"[{inet_ntop(ADDRESS_FAMILY.AF_INET6, row.ucLocalAddr)}]",
        local_port=htons(row.dwLocalPort),
        remote_addr=None,
        remote_port=None,
        state=None,
        pid=row.dwOwningPid,
    )


def get_active_connections() -> list[NetConnection]:
    tcp4_table = get_netconn_table(
        GetExtendedTcpTable, ADDRESS_FAMILY.AF_INET, TCP_TABLE_CLASS.OWNER_PID_ALL, MIB_TCPTABLE_OWNER_PID
    )
    tcp4_conns = parse_netconn_rows(tcp4_table, MIB_TCPROW_OWNER_PID, tcp4_row_parser)

    tcp6_table = get_netconn_table(
        GetExtendedTcpTable, ADDRESS_FAMILY.AF_INET6, TCP_TABLE_CLASS.OWNER_PID_ALL, MIB_TCP6TABLE_OWNER_PID
    )
    tcp6_conns = parse_netconn_rows(tcp6_table, MIB_TCP6ROW_OWNER_PID, tcp6_row_parser)

    udp4_table = get_netconn_table(
        GetExtendedUdpTable, ADDRESS_FAMILY.AF_INET, UDP_TABLE_CLASS.OWNER_PID, MIB_UDPTABLE_OWNER_PID
    )
    udp4_conns = parse_netconn_rows(udp4_table, MIB_UDPROW_OWNER_PID, udp4_row_parser)

    udp6_table = get_netconn_table(
        GetExtendedUdpTable, ADDRESS_FAMILY.AF_INET6, UDP_TABLE_CLASS.OWNER_PID, MIB_UDP6TABLE_OWNER_PID
    )
    udp6_conns = parse_netconn_rows(udp6_table, MIB_UDP6ROW_OWNER_PID, udp6_row_parser)

    return tcp4_conns + tcp6_conns + udp4_conns + udp6_conns


def format_net_connections_csv(net_connections: list[NetConnection]) -> str:
    def formatter(connection: NetConnection) -> str:
        rhost = connection.remote_address if connection.remote_address else ""
        rport = str(connection.remote_port) if connection.remote_port else ""
        state = connection.state.name if connection.state else ""
        return ",".join(
            [connection.protocol.name, connection.local_address, str(connection.local_port), rhost, rport, state]
        )

    header = ",".join(["protocol", "local address", "local port", "remote address", "remote port", "state"])
    rows = "\n".join(formatter(connection) for connection in net_connections)

    return f"{header}\n{rows}"


def format_net_connections_json(net_connections: list[NetConnection], indent=0) -> str:
    return dumps(
        net_connections, default=lambda connection: connection.as_dict(), indent=indent if indent > 0 else None
    )


def format_net_connections_list(net_connections: list[NetConnection]) -> str:
    def formatter(connection: NetConnection) -> str:
        rhost = connection.remote_address if connection.remote_address else ""
        rport = str(connection.remote_port) if connection.remote_port else ""
        state = connection.state.name if connection.state else ""

        lconn = f"{connection.local_address}:{str(connection.local_port)}"
        if connection.protocol in [CONNECTION_PROTOCOL.TCP4, CONNECTION_PROTOCOL.TCP6]:
            rconn = f"{rhost}:{rport}"
        else:
            rconn = "*:*"

        return f"{connection.protocol.name:<10}{lconn:<40}{rconn:<40}" f"{state:<20}{str(connection.pid):<10}"

    header = f"{'Proto':<10}{'Local Address':<40}{'Foreign Address':<40}{'State':<20}{'PID':<10}"
    header += "\n" + ("=" * len(header))
    rows = "\n".join(formatter(connection) for connection in net_connections)

    return f"{header}\n{rows}"
