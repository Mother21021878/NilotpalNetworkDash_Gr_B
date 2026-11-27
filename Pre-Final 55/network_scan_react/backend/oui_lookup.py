import os

OUI_DATABASE = {}

def load_database():

    global OUI_DATABASE

    if OUI_DATABASE:
        return

    path = os.path.join(
        os.path.dirname(__file__),
        "oui.txt"
    )

    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            parts = line.split(None,1)

            if len(parts)!=2:
                continue

            prefix = (
                parts[0]
                .replace("-", "")
                .replace(":", "")
                .strip()
                .upper()
            )

            vendor = parts[1]

            OUI_DATABASE[prefix]=vendor

def lookup_vendor(mac):

    load_database()

    prefix = (
        mac.replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .strip()
        .upper()[:6]
    )

    return OUI_DATABASE.get(prefix,"")