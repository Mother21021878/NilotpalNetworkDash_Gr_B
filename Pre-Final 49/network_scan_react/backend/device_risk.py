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
    breakdown = []

    
    # SNMP
    if device.get("snmpEnabled"):
        impact = DEVICE_RISK_RULES["SNMP"]
        score += impact

        reasons.append({
            "icon": "📡",
            "text": "SNMP service is enabled.",
            "severity": impact
        })

        breakdown.append({
            "factor": "SNMP Enabled",
            "impact": impact,
            "severity": "High",
            "description": "SNMP may expose sensitive management information."
        })

    
    # HTTP / HTTPS
    scheme = (device.get("httpScheme") or "").upper()

    if scheme == "HTTP":
        impact = DEVICE_RISK_RULES["HTTP"]
        score += impact

        reasons.append({
            "icon": "🌐",
            "text": "HTTP web interface detected.",
            "recommendation": "Enable HTTPS and disable unsecured HTTP access.",
            "severity": impact
        })

        breakdown.append({
            "factor": "HTTP",
            "impact": impact,
            "severity": "Medium",
            "description": "Unencrypted HTTP web access is exposed."
        })

    elif scheme == "HTTPS":
        impact = DEVICE_RISK_RULES["HTTPS"]
        score += impact

        breakdown.append({
            "factor": "HTTPS",
            "impact": impact,
            "severity": "Low",
            "description": "HTTPS web access is exposed."
        })

    elif device.get("httpBannerDetected"):
        impact = 6
        score += impact

        breakdown.append({
            "factor": "HTTP Banner Detected",
            "impact": impact,
            "severity": "Medium",
            "description": "An HTTP service was identified from the detected web banner."
        })

    
    # Services / Open Ports
    services = (device.get("services") or "").lower()

    open_ports = {
        str(port).strip()
        for port in str(device.get("openPorts", "")).split(",")
        if str(port).strip()
    }

    port_details = device.get("portDetails") or []

    def has_port(port):
        return str(port) in open_ports

    
    # Telnet
    if "telnet" in services or has_port(23):
        impact = DEVICE_RISK_RULES["TELNET"]
        score += impact

        reasons.append({
            "icon": "⚠️",
            "text": "Telnet service detected.",
            "recommendation": "Disable Telnet and use SSH for secure remote administration.",
            "severity": impact
        })

        breakdown.append({
            "factor": "Telnet",
            "impact": impact,
            "severity": "Critical",
            "description": "Telnet provides remote access without modern encrypted transport."
        })

    
    # FTP
    if "ftp" in services or has_port(21):
        impact = DEVICE_RISK_RULES["FTP"]
        score += impact

        reasons.append({
            "icon": "📁",
            "text": "FTP service detected.",
            "recommendation": "Replace FTP with SFTP or FTPS.",
            "severity": impact
        })

        breakdown.append({
            "factor": "FTP",
            "impact": impact,
            "severity": "High",
            "description": "FTP service is exposed and may transmit credentials or data without encryption."
        })

    
    # SSH
    if (
        device.get("sshBannerDetected")
        or "ssh" in services
        or has_port(22)
    ):
        impact = DEVICE_RISK_RULES["SSH"]
        score += impact

        reasons.append({
            "icon": "🔑",
            "text": "SSH remote access available.",
            "recommendation": "Allow SSH only for trusted hosts and use key-based authentication.",
            "severity": impact
        })

        breakdown.append({
            "factor": "SSH",
            "impact": impact,
            "severity": "Low",
            "description": "SSH remote administration is exposed."
        })

    
    # RTSP
    if "rtsp" in services or has_port(554):
        impact = DEVICE_RISK_RULES["RTSP"]
        score += impact

        reasons.append({
            "icon": "📷",
            "text": "RTSP streaming service exposed.",
            "recommendation": "Restrict RTSP access to authorized clients only.",
            "severity": impact
        })

        breakdown.append({
            "factor": "RTSP",
            "impact": impact,
            "severity": "Medium",
            "description": "RTSP streaming service is exposed."
        })

    
    # SMB
    if (
        "smb" in services
        or has_port(445)
        or has_port(139)
    ):
        impact = DEVICE_RISK_RULES["SMB"]
        score += impact

        reasons.append({
            "icon": "🖥️",
            "text": "SMB file sharing detected.",
            "recommendation": "Disable SMBv1 and restrict file sharing permissions.",
            "severity": impact
        })

        breakdown.append({
            "factor": "SMB",
            "impact": impact,
            "severity": "High",
            "description": "SMB file-sharing service is exposed."
        })

    
    # Unknown Operating System
    if device.get("operatingSystem") == "Unknown":
        impact = DEVICE_RISK_RULES["Unknown OS"]
        score += impact

        reasons.append({
            "icon": "❓",
            "text": "Operating system could not be identified.",
            "recommendation": "Perform additional fingerprinting to identify the operating system.",
            "severity": impact
        })

        breakdown.append({
            "factor": "Unknown OS",
            "impact": impact,
            "severity": "Medium",
            "description": "The operating system could not be identified."
        })

    
    # Unknown Vendor
    manufacturer = (
        device.get("manufacturer") or ""
    ).strip().lower()

    if manufacturer in (
        "",
        "unknown",
        "n/a",
        "generic"
    ):
        impact = DEVICE_RISK_RULES["Unknown Vendor"]
        score += impact

        reasons.append({
            "icon": "🏭",
            "text": "Manufacturer information unavailable.",
            "recommendation": "Verify the device manually or improve discovery sources.",
            "severity": impact
        })

        breakdown.append({
            "factor": "Unknown Vendor",
            "impact": impact,
            "severity": "Medium",
            "description": "Manufacturer information is unavailable or unidentified."
        })

    
    # Cap final score at 100
    score = min(score, 100)

    
    # Determine risk level
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    
    # Sort reasons by severity/impact
    reasons.sort(
        key=lambda reason: reason["severity"],
        reverse=True
    )

    # severity is only an internal sorting value for reasons
    for reason in reasons:
        reason.pop("severity", None)

    
    # Sort actual score contributions
    breakdown.sort(
        key=lambda item: item["impact"],
        reverse=True
    )

    
    # Return complete risk result
    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "breakdown": breakdown
    }