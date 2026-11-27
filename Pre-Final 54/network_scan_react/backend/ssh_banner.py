import socket

CONNECT_TIMEOUT = 3

SSH_PORTS = [
    22,
    2222
]


def scan_ssh_banner(ip, port=None):

    result = {

        "success": False,
        "banner": "",
        "vendor": "",
        "product": "",
        "version": "",
        "protocol": "",
        "port": port,
        "osHint": "",
        "error": ""
    }

    if port is None:
        port = SSH_PORTS[0]

    sock = None

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip, port))
        banner = sock.recv(512).decode(
            errors="ignore"
        ).strip()

        result["success"] = True
        result["banner"] = banner

        parse_ssh_banner(
            banner,
            result
        )

    except Exception as ex:
        result["error"] = str(ex)

    finally:

        if sock:
            sock.close()

    return result


def parse_ssh_banner(
    banner,
    result
):

    banner_upper = banner.upper()
    parts = banner.split("-")

    if len(parts) >= 2:
        result["protocol"] = parts[1]
    

    if "OPENSSH" in banner_upper:
        result["vendor"] = "OpenSSH"

        try:

            version = banner_upper.split(
                "OPENSSH_"
            )[1].split()[0]

            result["version"] = version

        except Exception:

            pass

    elif "DROPBEAR" in banner_upper:
        result["vendor"] = "Dropbear"

    elif "UBUNTU" in banner_upper:
        result["vendor"] = "Ubuntu"

    elif "DEBIAN" in banner_upper:
        result["vendor"] = "Debian"

    elif "FREEBSD" in banner_upper:
        result["vendor"] = "FreeBSD"

    elif "MIKROTIK" in banner_upper:
        result["vendor"] = "MikroTik"

    elif "FORTINET" in banner_upper:
        result["vendor"] = "Fortinet"

    elif "JUNIPER" in banner_upper:
        result["vendor"] = "Juniper"

    elif "CISCO" in banner_upper:
        result["vendor"] = "Cisco"

    elif "SSH" in banner_upper:
        result["vendor"] = "Unknown SSH"

    elif "ALPINE" in banner_upper:
        result["vendor"] = "Alpine Linux"

    elif "BUSYBOX" in banner_upper:
        result["vendor"] = "BusyBox"

    elif "SYNOLOGY" in banner_upper:
        result["vendor"] = "Synology"

    elif "QNAP" in banner_upper:
        result["vendor"] = "QNAP"

    result["product"] = result["vendor"]

    if "UBUNTU" in banner_upper:
        result["osHint"] = "Ubuntu"

    elif "DEBIAN" in banner_upper:
        result["osHint"] = "Debian"

    elif "FREEBSD" in banner_upper:
        result["osHint"] = "FreeBSD"

    elif "ALPINE" in banner_upper:
        result["osHint"] = "Alpine Linux"

    elif "BUSYBOX" in banner_upper:
        result["osHint"] = "BusyBox"


if __name__ == "__main__":

    print(

        scan_ssh_banner(
            "192.168.0.1",
            22
        )
    )