import pyshark
import traceback
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError

CAPTURE_TIMEOUT = 2
LLDP_DISPLAY_FILTER = "lldp"
CDP_DISPLAY_FILTER = "cdp"
DEBUG_LLDP_CDP = False

def scan_lldp_cdp(interface):

    result = {
        "lldp": {},
        "cdp": {},
        "success": False,
        "error": ""
    }
    

    if not interface:
        result["error"] = "Capture interface not specified."
        return result

    try:

        with ThreadPoolExecutor(max_workers=2) as executor:

            future_lldp = executor.submit(
                scan_lldp,
                interface
            )

            future_cdp = executor.submit(
                scan_cdp,
                interface
            )

            try:
                lldp = future_lldp.result(timeout=CAPTURE_TIMEOUT + 1)
            except TimeoutError:
                lldp = {}

            try:
                cdp = future_cdp.result(timeout=CAPTURE_TIMEOUT + 1)
            except TimeoutError:
                cdp = {}

        result["lldp"] = lldp
        result["cdp"] = cdp

        result["success"] = bool(lldp or cdp)

        if DEBUG_LLDP_CDP:
            print("=" * 60)
            print(f"LLDP : {'Found' if lldp else 'Not Found'}")
            print(f"CDP  : {'Found' if cdp else 'Not Found'}")
            print("=" * 60)

        if not result["success"]:

            result["error"] = (
                "No LLDP/CDP neighbour detected."
            )

    except Exception as ex:

        result["error"] = str(ex)

        if DEBUG_LLDP_CDP:
            traceback.print_exc()

    return result

def scan_lldp(interface):

    neighbour = {}

    capture = None

    try:
        if not interface:
            return {}

        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=LLDP_DISPLAY_FILTER
        )

        capture.sniff(packet_count=1, timeout=CAPTURE_TIMEOUT)

        for packet in capture:

            if not hasattr(packet, "lldp"):
                continue

            lldp = packet.lldp

            neighbour = {

                "protocol": "LLDP",
                "timestamp": getattr(
                    packet,
                    "sniff_time",
                    ""
                ),
                "systemName":
                    getattr(
                        lldp,
                        "tlv_system_name",
                        ""
                    ),
                "systemDescription":
                    getattr(
                        lldp,
                        "tlv_system_description",
                        ""
                    ),
                "portId":
                    getattr(
                        lldp,
                        "tlv_port_id",
                        ""
                    ),
                "chassisId":
                    getattr(
                        lldp,
                        "tlv_chassis_id",
                        ""
                    ),
                "managementAddress":
                    getattr(
                        lldp,
                        "tlv_management_address",
                        ""
                    ),
                "capabilities":
                    getattr(
                        lldp,
                        "tlv_system_capabilities",
                        ""
                    )
            }

            if DEBUG_LLDP_CDP:
                print("=" * 60)
                print("LLDP Neighbour Found")
                print(neighbour)
                print("=" * 60)

            return neighbour

    except Exception as ex:
        if DEBUG_LLDP_CDP:
            print(f"LLDP Scan Error : {ex}")

    finally:

        if capture is not None:

            try:

                if hasattr(capture, "close"):
                    capture.close()

            except RuntimeError:
                # Event loop already closed
                pass

            except Exception:
                pass

            finally:
                capture = None

    return {}

def scan_cdp(interface):

    neighbour = {}

    capture = None

    try:
        if not interface:
            return {}

        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=CDP_DISPLAY_FILTER
        )

        capture.sniff(packet_count=1, timeout=CAPTURE_TIMEOUT)

        for packet in capture:

            if not hasattr(packet, "cdp"):
                continue

            cdp = packet.cdp

            neighbour = {

                "protocol": "CDP",
                "timestamp": getattr(
                    packet,
                    "sniff_time",
                    ""
                ),
                "deviceId":
                    getattr(
                        cdp,
                        "deviceid",
                        ""
                    ),
                "portId":
                    getattr(
                        cdp,
                        "portid",
                        ""
                    ),
                "platform":
                    getattr(
                        cdp,
                        "platform",
                        ""
                    ),
                "software":
                    getattr(
                        cdp,
                        "software_version",
                        ""
                    ),
                "managementAddress":
                    getattr(
                        cdp,
                        "nrgyz_management_address",
                        getattr(
                            cdp,
                            "management_address",
                            ""
                        )
                    ),
                "capabilities":
                    getattr(
                        cdp,
                        "capabilities",
                        ""
                    )
            }

            if DEBUG_LLDP_CDP:
                print("=" * 60)
                print("CDP Neighbour Found")
                print(neighbour)
                print("=" * 60)

            return neighbour 

    except Exception as ex:
        if DEBUG_LLDP_CDP:
            print(f"CDP Scan Error : {ex}")
            
    finally:

        if capture is not None:

            try:

                if hasattr(capture, "close"):
                    capture.close()

            except RuntimeError:
                # Event loop already closed
                pass

            except Exception:
                pass

            finally:
                capture = None

    return {}

if __name__ == "__main__":

    print(
        scan_lldp_cdp(
            "Ethernet"
        )
    )