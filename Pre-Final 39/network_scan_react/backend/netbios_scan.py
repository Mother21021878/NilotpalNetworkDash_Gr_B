import socket
from nmb.NetBIOS import NetBIOS


def get_netbios_info(ip, timeout=2):

    result = {
        "hostname": "",
        "workgroup": "",
        "deviceType": ""
    }

    try:

        nb = NetBIOS()
        names = nb.queryIPForName(
            ip,
            timeout=timeout
        )

        nb.close()

        if not names:
            return result

        # First name is normally the Computer Name
        result["hostname"] = names[0]

        # Remaining names may include Workgroup/Domain
        if len(names) > 1:
            result["workgroup"] = names[1]

        result["deviceType"] = "Windows Device"

    except (socket.timeout, OSError):
        pass

    except Exception:
        pass

    return result