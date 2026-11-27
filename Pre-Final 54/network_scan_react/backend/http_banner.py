import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

HTTP_TIMEOUT = 3

def scan_http_banner(ip, port=80):

    result = {
        "server": "",
        "title": "",
        "webServer": "",
        "product": "",
        "httpStatus": "",
        "scheme": "",
        "bannerSource": "",
        "contentLength": 0,
        "realm": "",
        "success": False,
        "error": ""
    }

    if port in (443, 8443):
        scheme = "https"
    else:
        scheme = "http"

    url = f"{scheme}://{ip}:{port}"

    try:

        response = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            verify=False,
            allow_redirects=True
        )

        result["httpStatus"] = response.status_code
        result["contentLength"] = len(response.text)

        server = response.headers.get("Server", "").strip()

        result["server"] = server
        result["webServer"] = server

        result["realm"] = response.headers.get(
            "WWW-Authenticate",
            ""
        )

        soup = BeautifulSoup(
            response.text or "",
            "html.parser"
        )

        if soup.title:
            title = soup.title.get_text(strip=True)
        else:
            title = ""

        result["title"] = title
        result["product"] = title if title else server
        result["scheme"] = scheme.upper()
        result["bannerSource"] = result["scheme"]
        result["success"] = True

    except Exception as ex:
        result["error"] = str(ex)

    return result