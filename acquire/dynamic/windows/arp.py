from __future__ import annotations

import ctypes
from json import dumps
from socket import inet_ntop

from acquire.dynamic.windows.iphlpapi import (
    ADDRESS_FAMILY,
    IF_OPER_STATUS,
    IF_TYPE,
    IP_ADAPTER_ADDRESSES,
    LPVOID,
    MIB_IPNET_ROW2,
    MIB_IPNET_TABLE2,
    NL_NEIGHBOR_STATE,
    NO_ERROR,
    ULONG,
    FreeMibTable,
    GetAdaptersAddresses,
    GetIpNetTable2,
)


def format_physical_address(data: bytes, length: int) -> str | None:
    if length > 0:
        return "-".join(f"{b:02X}" for b in data[:length])
    return None


class NetAdapter:
    def __init__(
        self,
        index: int,
        name: str,
        description: str,
        friendly_name: str,
        physical_address: str | None,
        mtu: int,
        type: IF_TYPE,
        status: IF_OPER_STATUS,
    ):
        self.index = index
        self.name = name
        self.description = description
        self.friendly_name = friendly_name
        self.physical_address = physical_address
        self.mtu = mtu
        self.type = type
        self.operation_status = status

    @staticmethod
    def from_adapter_addresses(addresses: IP_ADAPTER_ADDRESSES) -> NetAdapter:
        index = addresses.Index
        adapter_name = addresses.AdapterName.decode()
        adapter_desc = addresses.Description
        adapter_friendly = addresses.FriendlyName
        physical_addr = format_physical_address(addresses.PhysicalAddress, addresses.PhysicalAddressLength)
        mtu = addresses.Mtu
        type = IF_TYPE(addresses.IfType)
        status = IF_OPER_STATUS(addresses.OperStatus)

        return NetAdapter(
            index=index,
            name=adapter_name,
            description=adapter_desc,
            friendly_name=adapter_friendly,
            physical_address=physical_addr,
            mtu=mtu,
            type=type,
            status=status,
        )

    @staticmethod
    def header_fields() -> list[str]:
        return [
            "Index",
            "Adapter Name",
            "Description",
            "Friendly Name",
            "MAC Address",
            "MTU",
            "Type",
            "Operation Status",
        ]

    def as_dict(self, indent=0) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "description": self.description,
            "friendly_name": self.friendly_name,
            "mac": self.physical_address,
            "mtu": self.mtu,
            "type": self.type.name,
            "status": self.operation_status.name,
        }

    def __str__(self) -> str:
        return (
            f"NetAdapter(index={self.index}, name={self.name}, desc={self.description}"
            f", friendly={self.friendly_name}, mac={self.physical_address}, mtu={self.mtu}, type={self.type}"
            f", status={self.operation_status.name})"
        )


class NetNeighbor:
    def __init__(
        self,
        family: ADDRESS_FAMILY,
        address: str,
        mac: str | None,
        state: NL_NEIGHBOR_STATE,
        adapter: NetAdapter | None,
    ):
        self.family: ADDRESS_FAMILY = family
        self.address: str = address
        self.mac: str | None = mac
        self.state: NL_NEIGHBOR_STATE = state
        self.adapter: NetAdapter | None = adapter

    def as_dict(self) -> dict:
        return {
            "family": self.family.name,
            "address": self.address,
            "mac": self.mac if self.mac else "",
            "state": self.state.name,
            "adapter": self.adapter.as_dict(),
        }

    def __str__(self) -> str:
        return (
            f"NetNeighbor(family={self.family.name}, address={self.address},"
            f"mac={self.mac}, state={self.state.name}, adapter={self.adapter})"
        )


def get_windows_network_adapters() -> list[NetAdapter]:
    adapter_buffer_size = ULONG(0)
    GetAdaptersAddresses(ADDRESS_FAMILY.AF_UNSPEC, 0, LPVOID(0), LPVOID(0), ctypes.byref(adapter_buffer_size))

    if adapter_buffer_size == 0:
        return []

    buffer = ctypes.create_string_buffer(adapter_buffer_size.value)
    result = GetAdaptersAddresses(ADDRESS_FAMILY.AF_UNSPEC, 0, LPVOID(0), buffer, ctypes.byref(adapter_buffer_size))
    if result != NO_ERROR:
        return []

    adapters = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    adapter = adapters.contents

    network_adapters = []

    while True:
        network_adapters.append(NetAdapter.from_adapter_addresses(adapter))

        if not adapter.Next:
            break

        adapter = ctypes.cast(adapter.Next, ctypes.POINTER(IP_ADAPTER_ADDRESSES)).contents

    return network_adapters


def get_adapter_by_index(adapters: list[NetAdapter], index: int) -> NetAdapter | None:
    for adapter in adapters:
        if adapter.index == index:
            return adapter
    return None


def get_windows_net_neighbors(adapters: list[NetAdapter]) -> list[NetNeighbor]:
    table_pointer = ctypes.POINTER(MIB_IPNET_TABLE2)()
    result = GetIpNetTable2(ADDRESS_FAMILY.AF_UNSPEC, ctypes.byref(table_pointer))

    if result != NO_ERROR:
        return []

    table = table_pointer.contents
    rows = ctypes.cast(table.Table, ctypes.POINTER(MIB_IPNET_ROW2 * table.NumEntries)).contents

    neighbors = []

    for row in rows:
        if row.Address.si_family == ADDRESS_FAMILY.AF_INET:
            ipv4 = row.Address.Ipv4
            address = inet_ntop(ADDRESS_FAMILY.AF_INET, ipv4.sin_addr)
        elif row.Address.si_family == ADDRESS_FAMILY.AF_INET6:
            ipv6 = row.Address.Ipv6
            address = f"[{inet_ntop(ADDRESS_FAMILY.AF_INET6, ipv6.sin6_addr)}]"
        else:
            # We should not end up here, but let's gracefully continue in hope there is more valid data to parse.
            continue

        mac = format_physical_address(row.PhysicalAddress, row.PhysicalAddressLength)
        adapter = get_adapter_by_index(adapters, row.InterfaceIndex)
        neighbor = NetNeighbor(
            family=ADDRESS_FAMILY(row.Address.si_family),
            address=address,
            mac=mac,
            state=NL_NEIGHBOR_STATE(row.State),
            adapter=adapter,
        )
        neighbors.append(neighbor)

    FreeMibTable(table_pointer)

    return neighbors


def format_net_neighbors_csv(net_neighbors: list[NetNeighbor]) -> str:
    def formatter(neighbor: NetNeighbor) -> str:
        return f",".join(
            [str(neighbor.adapter.index), neighbor.address, neighbor.mac if neighbor.mac else "", neighbor.state.name]
        )

    header = ",".join(["interface_index", "ip_address", "mac", "state"])
    rows = "\n".join(formatter(neighbor) for neighbor in net_neighbors)

    return f"{header}\n{rows}"


def format_net_neighbors_json(net_neighbors: list[NetNeighbor], indent=0) -> str:
    return dumps(net_neighbors, default=lambda neighbor: neighbor.as_dict(), indent=indent if indent > 0 else None)


def format_net_neighbors_list(net_neighbors: list[NetNeighbor]) -> str:
    def formatter(neighbor: NetNeighbor) -> str:
        mac = neighbor.mac if neighbor.mac else ""
        return f"{neighbor.adapter.index:<10}{neighbor.address:<60}{mac:<20}{neighbor.state.name:<20}"

    header = f"{'ifIndex':<10}{'IP Address':<60}{'MAC Address':<20}{'State':<20}"
    header += "\n" + ("=" * len(header))
    rows = "\n".join(formatter(neighbor) for neighbor in net_neighbors)

    return f"{header}\n{rows}"
