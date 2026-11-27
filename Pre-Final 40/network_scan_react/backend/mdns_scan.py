import time
from zeroconf import Zeroconf, ServiceBrowser


class MDNSListener:

    def __init__(self):

        self.devices = {}

    def add_service(self, zc, service_type, name):

        try:

            info = zc.get_service_info(service_type, name)

            if not info:
                return

            addresses = info.parsed_addresses()

            if not addresses:
                return

            ip = addresses[0]

            self.devices[ip] = {
                "hostname": name.replace(service_type, ""),
                "service": service_type
            }

        except Exception:
            pass

    def update_service(self, *args):
        pass

    def remove_service(self, *args):
        pass


def scan_mdns(timeout=3):

    zeroconf = Zeroconf()
    listener = MDNSListener()

    service_types = [

        "_workstation._tcp.local.",
        "_http._tcp.local.",
        "_ipp._tcp.local.",
        "_airplay._tcp.local.",
        "_googlecast._tcp.local."

    ]

    browsers = []

    for service in service_types:

        browsers.append(
            ServiceBrowser(
                zeroconf,
                service,
                listener
            )
        )

    time.sleep(timeout)

    zeroconf.close()

    return listener.devices