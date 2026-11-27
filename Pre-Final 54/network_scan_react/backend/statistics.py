from collections import Counter


def build_statistics(devices):

    stats = {}

    stats["totalDevices"] = len(devices)

    stats["onlineDevices"] = sum(
        1 for d in devices
        if d.get("active")
    )

    stats["offlineDevices"] = (
        stats["totalDevices"]
        - stats["onlineDevices"]
    )

    stats["gatewayCount"] = sum(
        1 for d in devices
        if d.get("topologyRole") == "Gateway"
    )

    stats["switchCount"] = sum(
        1 for d in devices
        if d.get("topologyRole") == "Switch"
    )

    stats["accessPointCount"] = sum(
        1 for d in devices
        if d.get("topologyRole") == "Access Point"
    )

    stats["endpointCount"] = sum(
        1 for d in devices
        if d.get("topologyRole") == "Endpoint"
    )

    return stats