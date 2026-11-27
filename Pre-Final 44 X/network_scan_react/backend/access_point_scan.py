import socket


def discover_access_points(devices, gateway_id):
    """
    Detect Access Points from the discovered devices.

    Parameters
    ----------
    devices : list
        List returned from scanner.py

    gateway_id : str
        Endpoint ID of the gateway.

    Returns
    -------
    list
        List of Access Point objects.
    """

    access_points = []

    for device in devices:

        manufacturer = (device.get("manufacturer") or "").lower()
        hostname = (device.get("hostname") or "").lower()
        device_type = (device.get("deviceType") or "").lower()
        friendly_name = (device.get("friendlyName") or "").lower()
        model = (device.get("model") or "").lower()

        if (
            "access point" in device_type
            or "wireless access point" in device_type
            or "wifi" in device_type
            or "wireless" in friendly_name
            or "access point" in friendly_name
            or "ap" == hostname
            or "ubiquiti" in manufacturer
            or "aruba" in manufacturer
            or "ruckus" in manufacturer
            or "tp-link" in manufacturer
            or "tplink" in manufacturer
            or "unifi" in manufacturer
            or "access point" in model
        ):

            ap = device.copy()

            ap["deviceType"] = "Access Point"
            ap["connectionType"] = "Wireless"
            ap["parentId"] = gateway_id

            access_points.append(ap)

    return access_points