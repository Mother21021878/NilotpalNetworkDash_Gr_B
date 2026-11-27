import socket
import upnpclient

def discover_upnp(timeout=3):

    devices = {}

    try:
        discovered = upnpclient.discover(timeout=timeout)
        for device in discovered:
            ip = ""
            try:
                ip = socket.gethostbyname(device.location.split("/")[2].split(":")[0])
            except:
                continue

            devices[ip] = {
                "friendlyName": getattr(device, "friendly_name", ""),
                "manufacturer": getattr(device, "manufacturer", ""),
                "manufacturerURL": getattr(device, "manufacturer_url", ""),
                "model": getattr(device, "model_name", ""),
                "modelNumber": getattr(device, "model_number", ""),
                "serial": getattr(device, "serial_number", ""),
                "deviceType": getattr(device, "device_type", ""),
                "presentationURL": getattr(device, "presentation_url", ""),
                "udn": getattr(device, "udn", "")
            }

    except Exception as e:

        print("UPnP Discovery Error:", e)

    return devices