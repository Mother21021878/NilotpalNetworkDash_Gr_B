DEVICE_RISK_RULES = {
    "SNMP": 15,
    "HTTP": 8,
    "HTTPS": 2,
    "TELNET": 35,
    "FTP": 25,
    "SSH": 6,
    "RTSP": 10,
    "SMB": 12,
    "Unknown OS": 10,
    "Unknown Vendor": 8
}

def calculate_device_risk(device):

    score = 0
    reasons = []

    if device.get("snmpEnabled"):
        score += DEVICE_RISK_RULES["SNMP"]
        reasons.append({
            "icon": "📡",
            "text": "SNMP service is enabled.",
            "recommendation": "Use SNMPv3 with authentication and disable public community strings.",
            "severity": DEVICE_RISK_RULES["SNMP"]
        })

    scheme = (device.get("httpScheme") or "").upper()

    if scheme == "HTTP":
        score += DEVICE_RISK_RULES["HTTP"]
        reasons.append({
            "icon": "🌐",
            "text": "HTTP web interface detected.",
            "recommendation":"Enable HTTPS and disable unsecured HTTP access.",
            "severity": DEVICE_RISK_RULES["HTTP"]
        })

    elif scheme == "HTTPS":
        score += DEVICE_RISK_RULES["HTTPS"]

    elif device.get("httpBannerDetected"):
        score += 6

    services = (device.get("services") or "").lower()

    open_ports = {
        str(port).strip()
        for port in str(device.get("openPorts", "")).split(",")
        if str(port).strip()
    }

    port_details = device.get("portDetails") or []

    def has_port(port):
        return str(port) in open_ports

    if "telnet" in services or has_port(23):
        score += DEVICE_RISK_RULES["TELNET"]
        reasons.append({
            "icon": "⚠️",
            "text": "Telnet service detected.",
            "recommendation":"Disable Telnet and use SSH for secure remote administration.",
            "severity": DEVICE_RISK_RULES["TELNET"]

        })

    if "ftp" in services or has_port(21):
        score += DEVICE_RISK_RULES["FTP"]
        reasons.append({
            "icon": "📁",
            "text": "FTP service detected.",
            "recommendation":"Replace FTP with SFTP or FTPS.",
            "severity": DEVICE_RISK_RULES["FTP"]
        })

    if (
        device.get("sshBannerDetected")
        or "ssh" in services
        or has_port(22)
    ):
        score += DEVICE_RISK_RULES["SSH"]
        reasons.append({
            "icon": "🔑",
            "text": "SSH remote access available.",
            "recommendation":"Allow SSH only for trusted hosts and use key-based authentication.",
            "severity": DEVICE_RISK_RULES["SSH"]
        })

    if "rtsp" in services or has_port(554):
        score += DEVICE_RISK_RULES["RTSP"]
        reasons.append({
            "icon": "📷",
            "text": "RTSP streaming service exposed.",
            "recommendation":"Restrict RTSP access to authorized clients only.",
            "severity": DEVICE_RISK_RULES["RTSP"]
        })

    if (
        "smb" in services
        or has_port(445)
        or has_port(139)
    ):
        score += DEVICE_RISK_RULES["SMB"]
        reasons.append({
            "icon": "🖥️",
            "text": "SMB file sharing detected.",
            "recommendation":"Disable SMBv1 and restrict file sharing permissions.",
            "severity": DEVICE_RISK_RULES["SMB"]
        })

    if device.get("operatingSystem") == "Unknown":
        score += DEVICE_RISK_RULES["Unknown OS"]
        reasons.append({
            "icon": "❓",
            "text": "Operating system could not be identified.",
            "recommendation":"Perform additional fingerprinting to identify the operating system.",
            "severity": DEVICE_RISK_RULES["Unknown OS"]
        })

    manufacturer = (
        device.get("manufacturer") or ""
    ).strip().lower()

    if manufacturer in (
        "",
        "unknown",
        "n/a",
        "generic"
    ):
        score += DEVICE_RISK_RULES["Unknown Vendor"]

        reasons.append({
            "icon": "🏭",
            "text": "Manufacturer information unavailable.",
            "recommendation":"Verify the device manually or improve discovery sources.",
            "severity": DEVICE_RISK_RULES["Unknown Vendor"]
        })

    score = min(score, 100)

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    reasons.sort(
        key=lambda reason: reason["severity"],
        reverse=True
    )

    for reason in reasons:
        reason.pop("severity", None)
    
    return {
        "score": score,
        "level": level,
        "reasons": reasons
    }