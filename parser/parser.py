import xml.etree.ElementTree as ET


def _parse_cpe_vendor(cpe_string):
    """Extracts the vendor component from a CPE 2.2 URI
    (e.g. 'cpe:/a:openbsd:openssh:8.2p1' -> 'openbsd'). Returns None if the
    string isn't in the expected shape."""
    if not cpe_string:
        return None
    parts = cpe_string.split(":")
    return parts[2] if len(parts) > 2 and parts[2] else None


def _parse_ports(host_elem):
    """Parses the <ports> block of a single <host> element into a list of
    open-port dicts. Shared by every host so single-host and multi-host
    parsing stay in sync."""
    open_ports = []
    ports = host_elem.find("ports")
    if ports is None:
        return open_ports

    for port in ports.findall("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")

        # CPE is a <cpe> CHILD ELEMENT of <service> in nmap's XML schema,
        # not an attribute - e.g.
        # <service ...><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe></service>.
        # A service can (rarely) list more than one <cpe>; we take the
        # first, which is nmap's best/primary match.
        cpe = None
        if service is not None:
            cpe_elem = service.find("cpe")
            if cpe_elem is not None and cpe_elem.text:
                cpe = cpe_elem.text.strip()

        port_data = {
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": state.get("state"),
            "service": service.get("name") if service is not None else None,
            "product": service.get("product") if service is not None else None,
            # nmap does not expose a separate "vendor" attribute on
            # <service> - derive it from the CPE string when one is
            # available, rather than reading a field that was never
            # actually there (it previously always returned None).
            "vendor": _parse_cpe_vendor(cpe),
            "version": service.get("version") if service is not None else None,
            "cpe": cpe,
            "extrainfo": service.get("extrainfo") if service is not None else None,
            "method": service.get("method") if service is not None else None,
            "conf": service.get("conf") if service is not None else None,
        }

        open_ports.append(port_data)

    return open_ports


def _parse_host(host_elem):
    """Parses a single <host> element into a rich host dict. Returns None
    if the host is not up/usable (down, unknown, skipped) per Nmap's own
    <status> element."""
    status = host_elem.find("status")
    if status is None or status.get("state") != "up":
        return None

    target = None
    address_type = None
    mac_address = None
    mac_vendor = None

    # A <host> can list more than one <address> - typically one ipv4/ipv6
    # address (the scan target) and, on local-network scans, a separate
    # mac address discovered via ARP. Nmap does not guarantee element
    # order, so we scan all of them rather than assuming the first is the
    # primary IP.
    for address in host_elem.findall("address"):
        addrtype = address.get("addrtype")
        if addrtype == "mac":
            mac_address = address.get("addr")
            mac_vendor = address.get("vendor")
        elif addrtype in ("ipv4", "ipv6") and target is None:
            target = address.get("addr")
            address_type = addrtype

    # Fallback for any address type we didn't recognize above (rare, but
    # keeps a target from silently being None if nmap ever adds a new type).
    if target is None:
        address = host_elem.find("address")
        if address is not None:
            target = address.get("addr")
            address_type = address.get("addrtype")

    hostname = None
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        hostname_elem = hostnames_elem.find("hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name")

    os_name = None
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch = os_elem.find("osmatch")
        if osmatch is not None:
            os_name = osmatch.get("name")

    return {
        "target": target,
        "address_type": address_type,
        "mac_address": mac_address,
        "mac_vendor": mac_vendor,
        "hostname": hostname,
        "os": os_name,
        "state": status.get("state"),
        "open_ports": _parse_ports(host_elem),
    }


def parse_nmap_xml(file_path):
    """Parses an Nmap XML output file into a structure describing every
    up/usable host it found.

    Returns:
        {
            "target": <ip of the first up host, or None>,   # back-compat
            "os": <os name of the first up host, or None>,  # back-compat
            "open_ports": [...],   # open ports of the first up host, back-compat
            "hosts": [ { "target", "address_type", "mac_address",
                         "mac_vendor", "hostname", "os", "state",
                         "open_ports": [...] }, ... ],
        }

    The top-level "target" / "os" / "open_ports" keys mirror the original
    single-host return shape exactly (they describe the first up host only)
    so every existing caller - scanner/pipeline.py, app/report.py, etc. -
    keeps working unchanged against a single-target scan, where the Nmap
    XML only ever contains one <host> anyway.

    The new "hosts" key holds every up host found, each with the same
    per-host fields, for callers that support multi-host results
    (e.g. the upcoming Network Scan feature).
    """
    tree = ET.parse(file_path)
    root = tree.getroot()

    hosts = []
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host is not None:
            hosts.append(host)

    result = {
        "target": None,
        "os": None,
        "open_ports": [],
        "hosts": hosts,
    }

    if hosts:
        first = hosts[0]
        result["target"] = first["target"]
        result["os"] = first["os"]
        result["open_ports"] = first["open_ports"]

    return result
