import ipaddress
import socket
import nmap
import traceback
import hashlib
import time
from datetime import datetime
from netbios_scan import get_netbios_info
from mdns_scan import scan_mdns
from upnp_scan import discover_upnp
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from packet_capture import get_connection_type
from oui_lookup import lookup_vendor
from snmp_scan import scan_snmp
from http_banner import scan_http_banner
from device_risk import calculate_device_risk
from lldp_cdp_scan import scan_lldp_cdp
from ssh_banner import (scan_ssh_banner, SSH_PORTS)
from access_point_scan import discover_access_points

HTTP_PORTS = {
    80,
    443,
    8080,
    8443
}

VENDOR_MAP = {
    "hp": "HP",
    "dell": "Dell",
    "lenovo": "Lenovo",
    "canon": "Canon",
    "epson": "Epson",
    "apple": "Apple",
    "samsung": "Samsung",
    "xiaomi": "Xiaomi",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "hikvision": "Hikvision",
    "realtek": "Realtek",
    "intel": "Intel",
    "raspberry": "Raspberry Pi",
    "ubiquiti": "Ubiquiti",
    "mikrotik": "MikroTik",
    "asus": "ASUS",
    "acer": "Acer",
    "msi": "MSI",
    "sony": "Sony",
    "lg": "LG",
    "oppo": "OPPO",
    "vivo": "Vivo",
    "oneplus": "OnePlus",
    "huawei": "Huawei",
    "honor": "Honor",
    "brother": "Brother",
    "zebra": "Zebra",
    "cisco": "Cisco",
    "juniper": "Juniper",
    "fortinet": "Fortinet",
    "netgear": "Netgear",
    "d-link": "D-Link"
}

DEVICE_TYPE_MAP = {
    "windows": "Windows PC",
    "linux": "Linux System",
    "android": "Android Device",
    "ios": "Apple Device",
    "printer": "Printer",
    "router": "Router",
    "camera": "IP Camera",
    "switch": "Network Switch",
    "firewall": "Firewall",
    "nas": "NAS",
    "tv": "Smart TV"
}

def get_local_subnet():
    """
    Returns the local subnet in CIDR format.
    Example: 192.168.0.0/24
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()

    network = ipaddress.IPv4Network(
        local_ip + "/24",
        strict=False
    )

    return str(network)

def reverse_dns_lookup(ip):

    try:

        hostname, alias, addresses = socket.gethostbyaddr(ip)

        return {
            "hostname": hostname,
            "aliases": alias,
            "addresses": addresses,
            "success": True
        }

    except Exception:

        return {
            "hostname": "",
            "aliases": [],
            "addresses": [],
            "success": False
        }

def get_os(data):

    try:
        osmatch = data.get("osmatch", [])
        if osmatch:
            return osmatch[0].get("name", "")

    except Exception:
        pass

    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                product = data[proto][port].get("product", "")
                version = data[proto][port].get("version", "")
                if product:
                    if version:
                        return f"{product} {version}"

                    return product

    except Exception:
        pass

    return ""

def get_open_ports(data):

    ports = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                if data[proto][port]["state"] == "open":
                    ports.append(str(port))

    except Exception:
        pass

    return ", ".join(
        sorted(
            ports,
            key=int
        )
    )

def get_port_details(data):

    ports = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                if data[proto][port]["state"] == "open":
                    ports.append({
                        "protocol": proto,
                        "port": port,
                        "service": data[proto][port].get("name", ""),
                        "product": data[proto][port].get("product", ""),
                        "version": data[proto][port].get("version", "")
                    })

    except Exception:
        pass

    return ports

def get_services(data):

    services = []
    try:

        for proto in data.all_protocols():
            for port in data[proto]:
                service = data[proto][port].get("name", "")
                if service:
                    services.append(service)

    except Exception:
        pass

    return ", ".join(sorted(set(services)))

def get_local_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    except Exception:
        return ""

    finally:
        s.close()

def get_default_gateway():

    try:

        import subprocess

        output = subprocess.check_output(
            "ipconfig",
            shell=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        for line in output.splitlines():

            if "Default Gateway" in line:

                gateway = line.split(":")[-1].strip()

                if gateway:
                    return gateway

    except Exception:
        pass

    return ""

def build_network_topology(devices):

    topology = {
        "gateway": None,
        "switches": [],
        "accessPoints": [],
        "devices": [],
        "summary": {
            "gatewayCount": 0,
            "switchCount": 0,
            "accessPointCount": 0,
            "deviceCount": 0
        }
    }

    for device in devices:

        device["parentId"] = None
        device["childCount"] = 0
        device["topologyChildren"] = []
        device["topologyLevel"] = 3
        device["linkConfidence"] = "Low"
        device["parentLinkType"] = ""
        device["topologyParentName"] = ""
        device["topologyPath"] = ""
        device["topologyRole"] = "Endpoint"

        device_type = (
            device.get("deviceType") or ""
        ).lower()

        manufacturer = (
            device.get("manufacturer") or ""
        ).lower()

        hostname = (
            device.get("hostname") or ""
        ).lower()

        device_type = (
            device.get("deviceType") or ""
        ).lower()

        friendly_name = (
            device.get("friendlyName") or ""
        ).lower()

        if (
            device.get("isGateway")
            or "router" in device_type
            or "gateway" in device_type
            or "internetgatewaydevice" in device_type
            or "wfadevice" in device_type
            or "access point" in friendly_name
            or "vantiva" in manufacturer
            or "openwrt" in hostname
        ):

            topology["gateway"] = device
            device["topologyLevel"] = 0
            device["topologyRole"] = "Gateway"

        elif (
            "switch" in device_type
            or device.get("lldpSystemName")
            or device.get("cdpDeviceId")
        ):

            topology["switches"].append(device)
            device["topologyLevel"] = 1
            device["topologyRole"] = "Switch"

        elif "access point" in device_type:

            topology["accessPoints"].append(device)
            device["topologyLevel"] = 2
            device["topologyRole"] = "Access Point"

        else:

            topology["devices"].append(device)

        topology["summary"]["gatewayCount"] = (
            1 if topology["gateway"] else 0
        )

        topology["summary"]["switchCount"] = len(topology["switches"])

        topology["summary"]["accessPointCount"] = len(topology["accessPoints"])

        topology["summary"]["deviceCount"] = len(topology["devices"])
    
    # Attach all discovered devices to the Gateway
    
    gateway = topology.get("gateway")

    if gateway:

        gateway_id = gateway.get("endpointId")

        endpoint_lookup = {
            device["endpointId"]: device
            for device in devices
        }

        hostname_lookup = {}
        mac_lookup = {}
        ip_lookup = {}
        friendly_lookup = {}

        for device in devices:

            hostname = (device.get("hostname") or "").strip().lower()
            if hostname:
                hostname_lookup[hostname] = device["endpointId"]

            mac = (device.get("mac") or "").strip().lower()
            if mac:
                mac_lookup[mac] = device["endpointId"]

            ip = (device.get("ip") or "").strip()
            if ip:
                ip_lookup[ip] = device["endpointId"]

            friendly = (device.get("friendlyName") or "").strip().lower()
            if friendly:
                friendly_lookup[friendly] = device["endpointId"]

        def find_neighbour_endpoint(device):

            # LLDP System Name
            system_name = (
                device.get("lldpSystemName") or ""
            ).strip().lower()

            if system_name and system_name in hostname_lookup:
                endpoint_id = hostname_lookup[system_name]

                return (
                    endpoint_lookup[endpoint_id],
                    "LLDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            if system_name and system_name in friendly_lookup:

                endpoint_id = friendly_lookup[system_name]

                return (
                    endpoint_lookup[endpoint_id],
                    "LLDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            # CDP Device ID
            cdp_name = (
                device.get("cdpDeviceId") or ""
            ).strip().lower()

            if cdp_name and cdp_name in hostname_lookup:

                endpoint_id = hostname_lookup[cdp_name]

                return (
                    endpoint_lookup[endpoint_id],
                    "CDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            if cdp_name and cdp_name in friendly_lookup:

                endpoint_id = friendly_lookup[cdp_name]

                return (
                    endpoint_lookup[endpoint_id],
                    "CDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            # LLDP Management IP
            mgmt_ip = (
                device.get("lldpManagementAddress") or ""
            ).strip()

            if mgmt_ip and mgmt_ip in ip_lookup:

                endpoint_id = ip_lookup[mgmt_ip]

                return (
                    endpoint_lookup[endpoint_id],
                    "LLDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            # CDP Management IP
            mgmt_ip = (
                device.get("cdpManagementAddress") or ""
            ).strip()

            if mgmt_ip and mgmt_ip in ip_lookup:

                endpoint_id = ip_lookup[mgmt_ip]

                return (
                    endpoint_lookup[endpoint_id],
                    "CDP",
                    device.get("lldpPortId", ""),
                    device.get("cdpPortId", "")
                )

            return (
                None,
                "",
                "",
                ""
            )

        access_points = topology["accessPoints"]

        for device in topology["devices"]:

            if device is gateway:
                continue

            connection = (
                device.get("connectionType") or ""
            ).lower()

            if connection == "wireless" and access_points:

                device["parentLinkType"] = "Wireless AP"
                index = (
                    abs(hash(device.get("endpointId", "")))
                    % len(access_points)
                )

                selected_ap = access_points[index]

                if selected_ap["endpointId"] != device["endpointId"]:
                    device["parentId"] = selected_ap["endpointId"]

                device["link"]["remoteDevice"] = (
                    access_points[index].get("hostname")
                    or access_points[index].get("friendlyName")
                    or access_points[index].get("ip")
                    or access_points[index].get("endpointId")
                )

            else:

                (
                    parent_device,
                    protocol,
                    local_port,
                    remote_port
                ) = find_neighbour_endpoint(device)

                if parent_device:

                    if parent_device["endpointId"] != device["endpointId"]:
                        device["parentId"] = parent_device["endpointId"]
                    device["link"]["localPort"] = local_port
                    device["link"]["remotePort"] = remote_port
                    device["link"]["parentInterface"] = remote_port
                    device["link"]["remoteDevice"] = (
                        parent_device.get("hostname")
                        or parent_device.get("friendlyName")
                        or parent_device.get("ip")
                        or parent_device.get("endpointId")
                    )
                    device["parentLinkType"] = protocol
                    device["linkConfidence"] = "High"

                elif topology["switches"]:

                    device["parentId"] = (
                        topology["switches"][0]["endpointId"]
                    )

                    device["link"]["remoteDevice"] = (
                        topology["switches"][0].get("hostname")
                        or topology["switches"][0].get("friendlyName")
                        or topology["switches"][0].get("ip")
                        or topology["switches"][0].get("endpointId")
                    )

                    device["parentLinkType"] = "Inferred Switch"
                    device["linkConfidence"] = "Medium"

                else:

                    device["parentId"] = gateway_id
                    device["link"]["remoteDevice"] = (
                        gateway.get("hostname")
                        or gateway.get("friendlyName")
                        or gateway.get("ip")
                        or gateway.get("endpointId")
                    )
                    device["parentLinkType"] = "Gateway"
                    device["linkConfidence"] = "Low"


        for switch in topology["switches"]:

            (
                parent_device,
                protocol,
                local_port,
                remote_port
            ) = find_neighbour_endpoint(switch)

            if parent_device:

                if parent_device["endpointId"] != switch["endpointId"]:
                    switch["parentId"] = parent_device["endpointId"]
                switch["link"]["localPort"] = local_port
                switch["link"]["remotePort"] = remote_port
                switch["link"]["parentInterface"] = remote_port
                switch["link"]["remoteDevice"] = (
                    parent_device.get("hostname")
                    or parent_device.get("friendlyName")
                    or parent_device.get("ip")
                    or parent_device.get("endpointId")
                )
                switch["parentLinkType"] = protocol
                switch["linkConfidence"] = "High"

            else:

                switch["parentId"] = gateway_id
                switch["parentLinkType"] = "Gateway"
                switch["linkConfidence"] = "Medium"

        for ap in topology["accessPoints"]:

            (
                parent_device,
                protocol,
                local_port,
                remote_port
            ) = find_neighbour_endpoint(ap)

            if parent_device:

                if parent_device["endpointId"] != ap["endpointId"]:
                    ap["parentId"] = parent_device["endpointId"]
                ap["link"]["localPort"] = local_port
                ap["link"]["remotePort"] = remote_port
                ap["link"]["parentInterface"] = remote_port
                ap["link"]["remoteDevice"] = (
                    parent_device.get("hostname")
                    or parent_device.get("friendlyName")
                    or parent_device.get("ip")
                    or parent_device.get("endpointId")
                )
                ap["parentLinkType"] = protocol
                ap["linkConfidence"] = "High"

            elif topology["switches"]:

                ap["parentId"] = topology["switches"][0]["endpointId"]
                ap["parentLinkType"] = "Switch"
                ap["linkConfidence"] = "Medium"

            else:

                ap["parentId"] = gateway_id
                ap["parentLinkType"] = "Gateway"
                ap["linkConfidence"] = "Low"

        parent_lookup = {}

        for device in devices:

            parent = device.get("parentId")

            if parent:
                parent_lookup[parent] = (
                    parent_lookup.get(parent, 0) + 1
                )

        for device in devices:

            endpoint = device["endpointId"]

            device["childCount"] = (
                parent_lookup.get(
                    endpoint,
                    0
                )
            )

            device["topologyChildren"] = [
                child["endpointId"]
                for child in devices
                if child.get("parentId") == endpoint
            ]

        name_lookup = {
            device["endpointId"]: (
                device.get("hostname")
                or device.get("friendlyName")
                or device.get("ip")
                or device["endpointId"]
            )
            for device in devices
        }

        for device in devices:

            path = []

            current = device

            visited = set()

            while current:

                endpoint = current["endpointId"]

                if endpoint in visited:
                    break

                visited.add(endpoint)

                path.append(
                    name_lookup.get(
                        endpoint,
                        endpoint
                    )
                )

                parent_id = current.get("parentId")

                if not parent_id:
                    break

                current = endpoint_lookup.get(parent_id)

            device["topologyPath"] = " > ".join(
                reversed(path)
            )

            parent_id = device.get("parentId")

            if parent_id:

                parent = endpoint_lookup.get(parent_id)

                if parent:
                    device["topologyParentName"] = (
                        parent.get("hostname")
                        or parent.get("friendlyName")
                        or parent.get("ip")
                        or parent["endpointId"]
                    )
    
    return topology

def scan_network():

    # scan_time = datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    scan_time = time.time()

    try:
        nm = nmap.PortScanner(
            nmap_search_path=(
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe"
            )
        )

    except Exception as e:
        raise Exception(f"Nmap initialization failed : {e}")

    subnet = get_local_subnet()

    with ThreadPoolExecutor(max_workers=3) as executor:

        future_mdns = executor.submit(scan_mdns)
        future_upnp = executor.submit(discover_upnp)

        nm.scan(
            hosts=subnet,
            arguments="-O -sV -Pn --osscan-guess --host-timeout 20s"
        )

        mdns_devices = future_mdns.result()
        upnp_devices = future_upnp.result()


    devices = []
    gateway_device = None

    hosts = sorted(
        nm.all_hosts(),
        key=lambda ip: tuple(map(int, ip.split(".")))
    )

    snmp_devices = {}

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(scan_snmp, host): host
            for host in hosts
        }

        for future in as_completed(futures):

            host = futures[future]
            try:
                snmp_devices[host] = future.result()
            except Exception:
                snmp_devices[host] = {}

    netbios_devices = {}

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = {
            executor.submit(get_netbios_info, host): host
            for host in hosts
        }

        for future in as_completed(futures):

            host = futures[future]

            try:
                netbios_devices[host] = future.result()

            except Exception:
                netbios_devices[host] = {}

    reverse_dns_cache = {}

    connection_type = get_connection_type()

    lldp_cdp_cache = {}

    try:

        if (
            connection_type
            and
            "Ethernet" in connection_type
        ):

            lldp_start = time.time()
            print(f"Scanning LLDP/CDP on {connection_type}...")
            lldp_cdp_cache = scan_lldp_cdp(
                connection_type
            )

            elapsed = time.time() - lldp_start

            print(
                f"LLDP/CDP scan completed in "
                f"{elapsed:.2f} sec."
            )

            if lldp_cdp_cache.get("success"):
                print("LLDP/CDP neighbour detected.")

            else:
                print("No LLDP/CDP neighbour detected.")

    except Exception:
        traceback.print_exc()

    local_ip = get_local_ip()
    default_gateway = get_default_gateway()
    http_banner_cache = {}
    ssh_banner_cache = {}
    
    for host in hosts:

        try:
            data = nm[host]
            netbios = netbios_devices.get(host) or {}
            mdns = mdns_devices.get(host) or {}
            upnp = upnp_devices.get(host) or {}
            snmp = snmp_devices.get(host, {})

            device_info = {
                **netbios,
                **mdns,
                **upnp,
                **snmp
            }

            # LLDP/CDP describes the local PC's directly connected neighbour.
            # Do not reuse it for every discovered device.

            lldp = {}
            cdp = {}

            if host == local_ip:
                lldp = lldp_cdp_cache.get("lldp", {})
                cdp = lldp_cdp_cache.get("cdp", {})

            vendor = ""
            hostname = ""
            hostname_source = "Unknown"
            model = ""
            device_type = ""
            os_name = ""
            open_ports = ""
            services = ""
            dns_name = ""

            original_mac = ""

            if "addresses" in data:
                original_mac = data["addresses"].get("mac", "")

            mac = original_mac.replace(":", "-").upper()
            ip_version = "IPv6" if ":" in host else "IPv4"

            vendor = ""
            vendor_source = "Unknown"

            # IEEE
            if original_mac:
                vendor = lookup_vendor(original_mac)
                if vendor:
                    vendor_lower = vendor.lower()

                    for key, value in VENDOR_MAP.items():
                        if key in vendor_lower:
                            vendor = value
                            break

                    vendor_source = "IEEE OUI"

            # Nmap
            if not vendor and original_mac and "vendor" in data:
                vendor = data["vendor"].get(original_mac, "")
                if vendor:
                    vendor_lower = vendor.lower()

                    for key, value in VENDOR_MAP.items():
                        if key in vendor_lower:
                            vendor = value
                            break

                if vendor:
                    vendor_source = "Nmap"

            # UPnP
            if not vendor and upnp.get("manufacturer"):
                vendor = upnp["manufacturer"]
                vendor_source = "UPnP"

            # mDNS
            if not vendor and mdns.get("manufacturer"):
                vendor = mdns["manufacturer"]
                vendor_source = "mDNS"


            if data.hostnames():
                hostname = data.hostnames()[0].get("name", "")

            if device_info.get("friendlyName"):

                hostname = device_info["friendlyName"]
                hostname_source = "UPnP"

            elif device_info.get("hostname"):

                hostname = device_info["hostname"]

                if mdns.get("hostname"):
                    hostname_source = "mDNS"

                elif netbios.get("hostname"):
                    hostname_source = "NetBIOS"

                else:
                    hostname_source = "Device"

            elif hostname:
                hostname_source = "Nmap"

            elif snmp.get("systemName"):
                hostname = snmp["systemName"]
                hostname_source = "SNMP"

            dns = {
                "hostname": "",
                "aliases": [],
                "addresses": [],
                "success": False
            }

            if not hostname:
                dns = reverse_dns_cache.get(host)

                if dns is None:
                    dns = reverse_dns_lookup(host)
                    reverse_dns_cache[host] = dns

                hostname = dns["hostname"]

                if dns["success"]:
                    hostname_source = "Reverse DNS"

            # Fallback
            if not hostname:
                hostname = host
                hostname_source = "IP Address"

            dns_name = dns["hostname"] if dns["success"] else ""

            workgroup = netbios.get("workgroup", "")

            response = "Unknown"

            try:
                if "times" in data:
                    srtt = data["times"].get("srtt")
                    if srtt is not None:
                        response = f"{srtt/1000:.2f} ms"

            except Exception:
                pass

            raw = "|".join([
                mac,
                upnp.get("udn", ""),
                upnp.get("serial", ""),
                hostname.lower(),
                host
            ])

            if raw.strip():
                endpoint_id = "DEV-" + hashlib.md5(raw.encode()).hexdigest()[:12].upper()
            else:
                endpoint_id = f"DEV-{host.replace('.', '')}"

            os_confidence = "Unknown"
            try:
                os_name = get_os(data)

                try:
                    if data.get("osmatch"):
                        os_confidence = data["osmatch"][0].get("accuracy", 0)
                except Exception:
                    pass

                model = (
                    device_info.get("model")
                    or upnp.get("model")
                    or upnp.get("modelNumber")
                    or upnp.get("friendlyName")
                    or snmp.get("systemDescription")
                    or mdns.get("model")
                    or netbios.get("model")
                    or ""
                )
            except Exception:
                pass

            port_details = get_port_details(data)
            open_ports = get_open_ports(data)
            services = get_services(data)
            classification_text = (
                    f"{os_name} "
                    f"{hostname} "
                    f"{model}"
                ).lower()


            # HTTP / HTTPS Banner Detection
            http_banner = {}
            ssh_banner = {}

            for port in port_details:

                service = port.get("service", "").lower()

                # HTTP / HTTPS
                if (
                    port["port"] in HTTP_PORTS
                    or "http" in service
                    or "https" in service
                ):

                    cache_key = f"{host}:{port['port']}"

                    if cache_key not in http_banner_cache:

                        http_banner_cache[cache_key] = scan_http_banner(
                            host,
                            port["port"]
                        )

                    http_banner = http_banner_cache[cache_key]
                    if http_banner.get("success"):
                        break

                # SSH
                elif port["port"] in SSH_PORTS or "ssh" in service:

                    cache_key = f"{host}:{port['port']}"

                    if cache_key not in ssh_banner_cache:

                        ssh_banner_cache[cache_key] = scan_ssh_banner(
                            host,
                            port["port"]
                        )

                    ssh_banner = ssh_banner_cache[cache_key]
                    if ssh_banner.get("success"):
                        break

            for keyword, value in DEVICE_TYPE_MAP.items():

                if keyword in classification_text:
                    device_type = value
                    break

            if upnp.get("deviceType"):
                device_type = upnp["deviceType"]

            elif mdns.get("deviceType"):
                device_type = mdns["deviceType"]

            elif netbios.get("deviceType"):
                device_type = netbios["deviceType"]

            if ssh_banner.get("success"):

                banner = ssh_banner.get("banner", "").lower()

                if "openssh" in banner and device_type == "Unknown Device":
                    device_type = "Linux System"

                elif "cisco" in banner:
                    device_type = "Network Device"

                elif "dropbear" in banner:
                    device_type = "Embedded Device"

                elif "mikrotik" in banner:
                    device_type = "Router"

                elif "synology" in banner:
                    device_type = "NAS"

                elif "qnap" in banner:
                    device_type = "NAS"

                elif "fortinet" in banner:
                    device_type = "Firewall"

                elif "juniper" in banner:
                    device_type = "Network Device"

            
            # device_type = "Unknown Device"

            # Infer Connection Type
            device_connection_type = "Unknown"

            # Local scanning PC
            if host == local_ip:
                device_connection_type = connection_type

            # Infrastructure devices are almost always wired
            elif (
                "router" in device_type.lower()
                or "switch" in device_type.lower()
                or "firewall" in device_type.lower()
            ):
                device_connection_type = "Ethernet"

            # Access Points
            elif "access point" in device_type.lower():
                device_connection_type = "Ethernet"

            # Wireless clients discovered through Wi-Fi services
            elif (
                mdns
                and
                (
                    "_airplay" in str(mdns).lower()
                    or "_raop" in str(mdns).lower()
                    or "_googlecast" in str(mdns).lower()
                )
            ):
                device_connection_type = "Wireless"

            # Mobile devices
            elif (
                "android" in device_type.lower()
                or "apple device" in device_type.lower()
            ):
                device_connection_type = "Wireless"

            # Printers
            elif "printer" in device_type.lower():
                device_connection_type = "Ethernet"

            # Improve switch detection using LLDP/CDP
            if (
                host == local_ip
                and
                (
                    lldp.get("systemName")
                    or cdp.get("deviceId")
                )
            ):
                if device_type in (
                    "Unknown Device",
                    "Network Device"
                ):
                    device_type = "Network Switch"

            if "Printer" in device_type:
                category = "Peripheral"
            elif "Router" in device_type:
                category = "Infrastructure"
            elif "Switch" in device_type:
                category = "Infrastructure"
            elif "Firewall" in device_type:
                category = "Security"
            elif "Camera" in device_type:
                category = "Surveillance"
            elif "TV" in device_type:
                category = "Entertainment"
            else:
                category = "Endpoint"

            gateway_score = 0

            if host == default_gateway:
                gateway_score += 100

            if "router" in device_type.lower():
                gateway_score += 60

            if "gateway" in device_type.lower():
                gateway_score += 60

            if "internetgatewaydevice" in device_type.lower():
                gateway_score += 60

            if "firewall" in device_type.lower():
                gateway_score += 30

            if upnp.get("deviceType", "").lower().startswith("internetgatewaydevice"):
                gateway_score += 60

            vendor_lower = vendor.lower()

            if (
                "vantiva" in vendor_lower
                or "tp-link" in vendor_lower
                or "netgear" in vendor_lower
                or "mikrotik" in vendor_lower
                or "ubiquiti" in vendor_lower
                or "cisco" in vendor_lower
            ):
                gateway_score += 20


            if not vendor:
                vendor = (
                    upnp.get("manufacturer")
                    or mdns.get("manufacturer")
                    or vendor
                )

            if not vendor and hostname:
                text = f"{hostname} {model}".lower()
                for keyword, value in VENDOR_MAP.items():

                    if keyword in text:
                        vendor = value
                        break


            combined_services = set()

            if services:
                combined_services.update(services.split(", "))

            if mdns.get("service"):
                combined_services.add(mdns["service"])

            if upnp.get("serviceType"):
                combined_services.add(upnp["serviceType"])

            if netbios.get("service"):
                combined_services.add(netbios["service"])

            combined_services = [
                s.strip()
                for s in combined_services
                if s.strip()
            ]

            combined_services = sorted(
                combined_services,
                key=str.lower
            )

            service_categories = []

            for service in combined_services:

                s = service.lower()

                if "http" in s:
                    service_categories.append("Web")
                elif "ftp" in s:
                    service_categories.append("File Transfer")
                elif "ssh" in s:
                    service_categories.append("Remote Administration")
                elif "printer" in s:
                    service_categories.append("Printing")
                elif "dns" in s:
                    service_categories.append("DNS")
                elif "upnp" in s:
                    service_categories.append("Discovery")

            if (ssh_banner.get("success") and "Remote Administration" not in service_categories):
                service_categories.append("Remote Administration")    

            discovery_sources = set()

            if data.state() == "up":
                discovery_sources.add("Nmap")
            if dns["success"]:
                discovery_sources.add("Reverse DNS")
            if netbios:
                discovery_sources.add("NetBIOS")
            if mdns:
                discovery_sources.add("mDNS")
            if upnp:
                discovery_sources.add("UPnP")
            if vendor_source == "IEEE OUI":
                discovery_sources.add("IEEE OUI")
            if (ssh_banner.get("success") and "SSH Banner" not in discovery_sources):
                discovery_sources.add("SSH Banner")
            
            protocol_versions = {}
            if lldp:
                protocol_versions["LLDP"] = { "version": "IEEE 802.1AB" }
            if cdp:
                protocol_versions["CDP"] = { "version": "Cisco Discovery Protocol" }
            if snmp:
                protocol_versions["SNMP"] = { "version": snmp.get("snmpVersion", "v2c") }
            if mdns:
                protocol_versions["mDNS"] = { "version": "v1" }
            if netbios:
                protocol_versions["NetBIOS"] = { "version": "NBT" }
            if upnp:
                protocol_versions["UPnP"] = { "version": "SSDP/1.0" }
            if ssh_banner.get("success"):
                protocol_versions["SSH"] = {
                    "version": ssh_banner.get("version", ""),
                    "protocol": ssh_banner.get("protocol", "")
                }

            confidence = 20
            if dns["success"]:
                confidence += 10
            if netbios:
                confidence += 15
            if mdns:
                confidence += 20
            if upnp:
                confidence += 25
            if vendor:
                confidence += 10
            if model:
                confidence += 10
            if hostname and hostname != host:
                confidence += 10
            if open_ports:
                confidence += 10
            if mac:
                confidence += 5
            if device_type != "Unknown Device":
                confidence += 5
            if vendor_source == "IEEE OUI":
                confidence += 10
            if snmp.get("snmpEnabled"):
                confidence += 25
            if ssh_banner.get("success"):
                confidence += 8
            # if category == "Infrastructure":
            if host == local_ip:
                if lldp:
                    confidence += 10
                if cdp:
                    confidence += 10
            elif vendor_source == "Nmap":
                confidence += 5
            confidence = min(confidence, 100)

            if confidence >= 90:
                rank = "Excellent"
            elif confidence >= 70:
                rank = "Good"
            elif confidence >= 50:
                rank = "Fair"
            else:
                rank = "Low"

            protocol_count = sum([
                bool(dns["success"]),
                bool(netbios),
                bool(mdns),
                bool(upnp),
                snmp.get("snmpEnabled", False),
                ssh_banner.get("success", False),
                host == local_ip and bool(lldp),
                host == local_ip and bool(cdp)
            ])

            
            status = "Online" if data.state() == "up" else "Offline"

            last_protocol = ""

            if ssh_banner.get("success"):
                last_protocol = "SSH Banner"
            elif upnp:
                last_protocol = "UPnP"
            elif mdns:
                last_protocol = "mDNS"
            elif netbios:
                last_protocol = "NetBIOS"
            else:
                last_protocol = "Nmap"

            if snmp.get("snmpEnabled"):
                discovery_sources.add("SNMP")

            # if category == "Infrastructure":
            if host == local_ip:
                if lldp:
                    discovery_sources.add("LLDP")
                if cdp:
                    discovery_sources.add("CDP")

            discovery_sources = sorted(discovery_sources)

            device_signature = hashlib.sha1(
                (
                    host +
                    mac +
                    model +
                    vendor
                ).encode()
            ).hexdigest()

            device = {
                "endpointId": endpoint_id,
                "hostname": hostname,
                "hostnameSource": hostname_source,
                "workgroup": workgroup,
                "manufacturer": vendor,
                "manufacturerSource": vendor_source,
                "model": model if model else "Unknown",
                "modelNumber": upnp.get("modelNumber", ""),
                "friendlyName": upnp.get("friendlyName", ""),
                "ip": host,
                "isGateway": host == default_gateway,
                "gatewayScore": gateway_score,
                "mac": mac,
                "ipVersion": ip_version,
                "firmware": "Unknown",
                "software": "Unknown",
                "hardware": "Unknown",
                "deviceType": device_type,
                "dnsName": dns_name,
                "reverseDns": dns_name,
                "reverseDnsResolved": dns["success"],
                "dnsAliases": dns["aliases"],
                "dnsAddresses": dns["addresses"],
                # "connectionType": connection_type if host == local_ip else "Unknown",
                "connectionType": device_connection_type,
                "wifiBand": (
                    "2.4 GHz"
                    if connection_type == "Wireless"
                    else "-"
                ),

                "wifiChannel": (
                    "Auto"
                    if connection_type == "Wireless"
                    else "-"
                ),

                "ssid": (
                    hostname
                    if (
                        connection_type == "Wireless"
                        and device_type == "Access Point"
                    )
                    else "-"
                ),

                "rssi": (
                    "-55 dBm"
                    if connection_type == "Wireless"
                    else "-"
                ),
                "uptime": "Unknown",
                "scanTime": scan_time,
                "responseTime": response,
                "lastSeen": scan_time,
                "lastBoot": "Unknown",
                "active": data.state() == "up",
                "discoveryTimestamp": int(time.time()),
                "operatingSystem": os_name if os_name else "Unknown",
                "openPorts": open_ports,
                "portDetails": port_details,
                "openPortCount": len(open_ports.split(", ")) if open_ports else 0,
                "services": ", ".join(combined_services),
                "serviceCount": len(combined_services),
                "serviceCategories": sorted(set(service_categories)),
                "serial": upnp.get("serial", ""),
                "presentationURL": upnp.get("presentationURL", ""),
                "manufacturerURL": upnp.get("manufacturerURL", ""),
                "udn": upnp.get("udn", ""),
                "discoverySource": ", ".join(discovery_sources),
                "confidence": confidence,
                "rank": rank,
                "netbios": netbios,
                "mdns": mdns,
                "upnp": upnp,
                "protocolVersions": protocol_versions,
                "protocolCount": protocol_count,
                "scanDuration": 0,
                "status": status,
                "category": category,
                "deviceSignature": device_signature,
                "link": {
                    "localPort": "",
                    "remotePort": "",
                    "remoteDevice": "",
                    "parentInterface": "",
                    "label": ""
                },
                "firstDiscovered": scan_time,
                "lastDiscovered": scan_time,
                "mdnsAvailable": bool(mdns),
                "netbiosAvailable": bool(netbios),
                "upnpAvailable": bool(upnp),
                "lastDiscoveryProtocol": last_protocol,
                "primaryDiscoveryProtocol": discovery_sources[0] if discovery_sources else "",
                "osConfidence": os_confidence,
                "nmap": {
                    "hostnames": data.hostnames(),
                    "state": data.state(),
                    "vendor": data.get("vendor", {}),
                    "addresses": data.get("addresses", {})
                },
                "confidenceReason": {
                    "netbios": bool(netbios),
                    "mdns": bool(mdns),
                    "upnp": bool(upnp),
                    "snmp": snmp.get("snmpEnabled", False),
                    "ssh": ssh_banner.get("success", False),
                    "lldp": (
                        host == local_ip
                        and
                        bool(lldp)
                    ),
                    "cdp": (
                        host == local_ip
                        and
                        bool(cdp)
                    ),
                    "vendor": bool(vendor),
                    "model": bool(model),
                    "hostname": bool(hostname) and hostname != host,
                    "ports": bool(open_ports)
                },
                "snmpEnabled": snmp.get("snmpEnabled", False),
                "snmpVersion": snmp.get("snmpVersion",""),
                # LLDP
                "lldpSystemName": "",
                "lldpSystemDescription": "",
                "lldpPortId": "",
                "lldpChassisId": "",
                "lldpManagementAddress": "",
                "lldpCapabilities": "",
                # CDP
                "cdpDeviceId": "",
                "cdpPortId": "",
                "cdpPlatform": "",
                "cdpSoftware": "",
                "cdpManagementAddress": "",
                "cdpCapabilities": "",
                "systemDescription": snmp.get("systemDescription", ""),
                "systemName": snmp.get("systemName", ""),
                "systemLocation": snmp.get("location", ""),
                "systemContact": snmp.get("contact", ""),
                "systemUptime": snmp.get("uptime", ""),
                "systemObjectId": snmp.get("objectId", ""),
                "httpServer": http_banner.get("server", ""),
                "httpTitle": http_banner.get("title", ""),
                "httpProduct": http_banner.get("product", ""),
                "httpStatus": http_banner.get("httpStatus", ""),
                "httpScheme": http_banner.get("scheme", ""),
                "httpRealm": http_banner.get("realm", ""),
                "httpBannerSource": http_banner.get("bannerSource", ""),
                "httpContentLength": http_banner.get("contentLength", 0),
                "httpBannerDetected": http_banner.get("success", False),
                # SSH Banner
                "sshBannerDetected": ssh_banner.get("success", False),
                "sshBanner": ssh_banner.get("banner", ""),
                "sshVendor": ssh_banner.get("vendor", ""),
                "sshProduct": ssh_banner.get("product", ""),
                "sshVersion": ssh_banner.get("version", ""),
                "sshProtocol": ssh_banner.get("protocol", ""),
                "sshOsHint": ssh_banner.get("osHint", ""),
                "sshPort": ssh_banner.get("port", "")
                }

            # if category == "Infrastructure":
            if host == local_ip:
                device["lldpSystemName"] = lldp.get("systemName", "")
                device["lldpSystemDescription"] = lldp.get("systemDescription", "")
                device["lldpPortId"] = lldp.get("portId", "")
                device["lldpChassisId"] = lldp.get("chassisId", "")
                device["lldpManagementAddress"] = lldp.get("managementAddress", "")
                device["lldpCapabilities"] = lldp.get("capabilities", "")

                device["cdpDeviceId"] = cdp.get("deviceId", "")
                device["cdpPortId"] = cdp.get("portId", "")
                device["cdpPlatform"] = cdp.get("platform", "")
                device["cdpSoftware"] = cdp.get("software", "")
                device["cdpManagementAddress"] = cdp.get("managementAddress", "")
                device["cdpCapabilities"] = cdp.get("capabilities", "")

                device["link"]["localPort"] = (device["lldpPortId"] or device["cdpPortId"])
                device["link"]["remoteDevice"] = (device["lldpSystemName"] or device["cdpDeviceId"])
                device["link"]["remotePort"] = (device["cdpPortId"])
                device["link"]["parentInterface"] = (device["link"]["remotePort"])

                local_port = device["link"]["localPort"]
                remote_port = device["link"]["remotePort"]
                remote_device = device["link"]["remoteDevice"]

                if local_port and remote_port:

                    device["link"]["label"] = (
                        f"{local_port} → {remote_port}"
                    )

                elif local_port and remote_device:

                    device["link"]["label"] = (
                        f"{local_port} → {remote_device}"
                    )

                elif remote_device:

                    device["link"]["label"] = remote_device

                else:

                    device["link"]["label"] = ""

            else:
                device["lldpSystemName"] = ""
                device["lldpSystemDescription"] = ""
                device["lldpPortId"] = ""
                device["lldpChassisId"] = ""
                device["lldpManagementAddress"] = ""
                device["lldpCapabilities"] = ""

                device["cdpDeviceId"] = ""
                device["cdpPortId"] = ""
                device["cdpPlatform"] = ""
                device["cdpSoftware"] = ""
                device["cdpManagementAddress"] = ""
                device["cdpCapabilities"] = ""
            

            # Remember the first detected gateway
            if (
                gateway_device is None
                or device["gatewayScore"] > gateway_device["gatewayScore"]
            ):
                gateway_device = device
           
            devices.append(device)
            """"
            print(
                f"{host:15} "
                f"{'Online' if data.state()=='up' else 'Offline':8} "
                f"{vendor:20} "
                f"{hostname:20} "
                f"{os_name}"
            )
            """

        except Exception as e:
            print(f"Unable to scan {host} : {e}")
            traceback.print_exc()

    elapsed = round(time.time() - scan_time, 2)

    if elapsed < 1:
        scan_duration = f"{elapsed*1000:.0f} ms"

    elif elapsed < 60:
        scan_duration = f"{elapsed:.2f} sec"

    else:
        minutes = int(elapsed // 60)
        seconds = elapsed % 60

        scan_duration = f"{minutes} min {seconds:.2f} sec"
    
    for device in devices:
        device["scanDuration"] = scan_duration

    #print(f"Total Scan Duration : {scan_duration}")
    
    #print(f"Scan Completed : {len(devices)} device(s) found.")

    online = sum(1 for d in devices if d["active"])

    #print("=" * 60)
    #print(f"Online Devices : {online}")
    #print(f"Offline Devices: {len(devices) - online}")
    #print("=" * 60)

    for device in devices:
        device["isGateway"] = (
            gateway_device is not None
            and device["endpointId"] == gateway_device["endpointId"]
        )


    # Discover Wireless Access Points
    
    if gateway_device:

        gateway_id = gateway_device.get("endpointId")

        access_points = discover_access_points(
            devices,
            gateway_id
        )

        existing_ids = {
            device.get("endpointId")
            for device in devices
        }

        for ap in access_points:

            if ap.get("endpointId") not in existing_ids:
                devices.append(ap)

    for device in devices:

        risk = calculate_device_risk(device)

        device["deviceRiskScore"] = risk["score"]
        device["deviceRiskLevel"] = risk["level"]
        device["deviceRiskReasons"] = risk["reasons"]            

    return devices