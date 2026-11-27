DEVICE_RISK_ENGINE_VERSION = "device-risk-v2"
DEVICE_RISK_EXPLAINABILITY_VERSION = "1.1"
DEVICE_RISK_SCORE_CAP = 100

DEVICE_RISK_RULES = {
    "SNMP": {
        "weight": 15,
        "ruleId": "DEVICE-RISK-SNMP-001",
        "source": "snmp_scan",
        "sourceField": "snmpEnabled"
    },
    "HTTP": {
        "weight": 8,
        "ruleId": "DEVICE-RISK-HTTP-001",
        "source": "http_banner_scan",
        "sourceField": "httpScheme"
    },
    "HTTPS": {
        "weight": 2,
        "ruleId": "DEVICE-RISK-HTTPS-001",
        "source": "http_banner_scan",
        "sourceField": "httpScheme"
    },
    "HTTP Banner": {
        "weight": 6,
        "ruleId": "DEVICE-RISK-HTTP-BANNER-001",
        "source": "http_banner_scan",
        "sourceField": "httpBannerDetected"
    },
    "TELNET": {
        "weight": 35,
        "ruleId": "DEVICE-RISK-TELNET-001",
        "source": "nmap/service_detection",
        "sourceField": "services/openPorts"
    },
    "FTP": {
        "weight": 25,
        "ruleId": "DEVICE-RISK-FTP-001",
        "source": "nmap/service_detection",
        "sourceField": "services/openPorts"
    },
    "SSH": {
        "weight": 6,
        "ruleId": "DEVICE-RISK-SSH-001",
        "source": "ssh_banner_scan/nmap",
        "sourceField": "sshBannerDetected/services/openPorts"
    },
    "RTSP": {
        "weight": 10,
        "ruleId": "DEVICE-RISK-RTSP-001",
        "source": "nmap/service_detection",
        "sourceField": "services/openPorts"
    },
    "SMB": {
        "weight": 12,
        "ruleId": "DEVICE-RISK-SMB-001",
        "source": "nmap/service_detection",
        "sourceField": "services/openPorts"
    },
    "Unknown OS": {
        "weight": 10,
        "ruleId": "DEVICE-RISK-OS-001",
        "source": "device_fingerprinting",
        "sourceField": "operatingSystem"
    },
    "Unknown Vendor": {
        "weight": 8,
        "ruleId": "DEVICE-RISK-VENDOR-001",
        "source": "oui_lookup/device_discovery",
        "sourceField": "manufacturer"
    }
}


def _add_reason(
    reasons,
    icon,
    text,
    recommendation,
    severity
):
    reason = {
        "icon": icon,
        "text": text,
        "severity": severity
    }

    if recommendation:
        reason["recommendation"] = recommendation

    reasons.append(reason)


def _add_breakdown(
    breakdown,
    rule_id,
    factor,
    impact,
    severity,
    description,
    source,
    source_field,
    observed_value,
    score_before,
    score_after,
    recommendation
):
    breakdown.append({
        "ruleId": rule_id,
        "factor": factor,
        "impact": impact,
        "scoreBefore": score_before,
        "scoreAfter": score_after,
        # This is corrected to the final capped score after raw_score is known.
        "scoreWithoutFactor": None,
        "remediationImpact": -impact,
        "severity": severity,
        "description": description,
        "recommendation": recommendation or "",
        "source": source,
        "sourceField": source_field,
        "observedValue": observed_value,
        "role": "Actual device risk-score contribution"
    })


def calculate_device_risk(device):
    """
    Deterministic device risk calculation with full explainability.

    Score:
        min(sum(applicable rule impacts), 100)

    Each applied rule records:
        - ruleId
        - evidence source
        - source field
        - observed value
        - score before/after
        - score without the factor
        - remediation impact
        - recommendation
    """

    score = 0
    reasons = []
    breakdown = []

    # ---------------------------------------------------------
    # SNMP
    # ---------------------------------------------------------

    if device.get("snmpEnabled"):
        impact = DEVICE_RISK_RULES["SNMP"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Use SNMPv3 where possible and restrict management access."
        )

        _add_reason(
            reasons,
            "📡",
            "SNMP service is enabled.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-SNMP-001",
            "SNMP Enabled",
            impact,
            "High",
            "SNMP may expose sensitive management information.",
            "snmp_scan",
            "snmpEnabled",
            True,
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # HTTP / HTTPS
    # ---------------------------------------------------------

    scheme = (
        device.get("httpScheme") or ""
    ).upper()

    if scheme == "HTTP":
        impact = DEVICE_RISK_RULES["HTTP"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Enable HTTPS and disable unsecured HTTP access."
        )

        _add_reason(
            reasons,
            "🌐",
            "HTTP web interface detected.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-HTTP-001",
            "HTTP",
            impact,
            "Medium",
            "Unencrypted HTTP web access is exposed.",
            "http_banner_scan",
            "httpScheme",
            scheme,
            score_before,
            score,
            recommendation
        )

    elif scheme == "HTTPS":
        impact = DEVICE_RISK_RULES["HTTPS"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Maintain HTTPS and use a valid, current certificate."
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-HTTPS-001",
            "HTTPS",
            impact,
            "Low",
            "HTTPS web access is exposed.",
            "http_banner_scan",
            "httpScheme",
            scheme,
            score_before,
            score,
            recommendation
        )

    elif device.get("httpBannerDetected"):
        impact = DEVICE_RISK_RULES["HTTP Banner"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Review the web service and use HTTPS where supported."
        )

        _add_reason(
            reasons,
            "🌐",
            "HTTP service identified from the detected web banner.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-HTTP-BANNER-001",
            "HTTP Banner Detected",
            impact,
            "Medium",
            "An HTTP service was identified from the detected web banner.",
            "http_banner_scan",
            "httpBannerDetected",
            True,
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # Services / Open Ports
    # ---------------------------------------------------------

    services = (
        device.get("services") or ""
    ).lower()

    open_ports = {
        str(port).strip()
        for port in str(
            device.get("openPorts", "")
        ).split(",")
        if str(port).strip()
    }

    def has_port(port):
        return str(port) in open_ports

    # ---------------------------------------------------------
    # Telnet
    # ---------------------------------------------------------

    if "telnet" in services or has_port(23):
        impact = DEVICE_RISK_RULES["TELNET"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Disable Telnet and use SSH for secure remote administration."
        )

        _add_reason(
            reasons,
            "⚠️",
            "Telnet service detected.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-TELNET-001",
            "Telnet",
            impact,
            "Critical",
            "Telnet provides remote access without modern encrypted transport.",
            "nmap/service_detection",
            "services/openPorts",
            {
                "service": "telnet" in services,
                "port23": has_port(23)
            },
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # FTP
    # ---------------------------------------------------------

    if "ftp" in services or has_port(21):
        impact = DEVICE_RISK_RULES["FTP"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Replace FTP with SFTP or FTPS."
        )

        _add_reason(
            reasons,
            "📁",
            "FTP service detected.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-FTP-001",
            "FTP",
            impact,
            "High",
            "FTP service is exposed and may transmit credentials or data without encryption.",
            "nmap/service_detection",
            "services/openPorts",
            {
                "service": "ftp" in services,
                "port21": has_port(21)
            },
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # SSH
    # ---------------------------------------------------------

    if (
        device.get("sshBannerDetected")
        or "ssh" in services
        or has_port(22)
    ):
        impact = DEVICE_RISK_RULES["SSH"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Allow SSH only for trusted hosts and use key-based authentication."
        )

        _add_reason(
            reasons,
            "🔑",
            "SSH remote access available.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-SSH-001",
            "SSH",
            impact,
            "Low",
            "SSH remote administration is exposed.",
            "ssh_banner_scan/nmap",
            "sshBannerDetected/services/openPorts",
            {
                "bannerDetected": bool(
                    device.get("sshBannerDetected")
                ),
                "service": "ssh" in services,
                "port22": has_port(22)
            },
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # RTSP
    # ---------------------------------------------------------

    if "rtsp" in services or has_port(554):
        impact = DEVICE_RISK_RULES["RTSP"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Restrict RTSP access to authorized clients only."
        )

        _add_reason(
            reasons,
            "📷",
            "RTSP streaming service exposed.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-RTSP-001",
            "RTSP",
            impact,
            "Medium",
            "RTSP streaming service is exposed.",
            "nmap/service_detection",
            "services/openPorts",
            {
                "service": "rtsp" in services,
                "port554": has_port(554)
            },
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # SMB
    # ---------------------------------------------------------

    if (
        "smb" in services
        or has_port(445)
        or has_port(139)
    ):
        impact = DEVICE_RISK_RULES["SMB"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Disable SMBv1 and restrict file sharing permissions."
        )

        _add_reason(
            reasons,
            "🖥️",
            "SMB file sharing detected.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-SMB-001",
            "SMB",
            impact,
            "High",
            "SMB file-sharing service is exposed.",
            "nmap/service_detection",
            "services/openPorts",
            {
                "service": "smb" in services,
                "port445": has_port(445),
                "port139": has_port(139)
            },
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # Unknown Operating System
    # ---------------------------------------------------------

    operating_system = (
        device.get("operatingSystem") or ""
    ).strip()

    if operating_system.lower() in (
        "",
        "unknown",
        "n/a",
        "n/a."
    ):
        impact = DEVICE_RISK_RULES["Unknown OS"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Perform additional fingerprinting to identify the operating system."
        )

        _add_reason(
            reasons,
            "❓",
            "Operating system could not be identified.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-OS-001",
            "Unknown OS",
            impact,
            "Medium",
            "The operating system could not be identified.",
            "device_fingerprinting",
            "operatingSystem",
            operating_system or "Unknown",
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # Unknown Vendor
    # ---------------------------------------------------------

    manufacturer = (
        device.get("manufacturer") or ""
    ).strip().lower()

    if manufacturer in (
        "",
        "unknown",
        "n/a",
        "generic"
    ):
        impact = DEVICE_RISK_RULES["Unknown Vendor"]["weight"]
        score_before = score
        score += impact

        recommendation = (
            "Verify the device manually or improve discovery sources."
        )

        _add_reason(
            reasons,
            "🏭",
            "Manufacturer information unavailable.",
            recommendation,
            impact
        )

        _add_breakdown(
            breakdown,
            "DEVICE-RISK-VENDOR-001",
            "Unknown Vendor",
            impact,
            "Medium",
            "Manufacturer information is unavailable or unidentified.",
            "oui_lookup/device_discovery",
            "manufacturer",
            device.get("manufacturer") or "Unknown",
            score_before,
            score,
            recommendation
        )

    # ---------------------------------------------------------
    # Final score and risk level
    # ---------------------------------------------------------

    raw_score = score
    score_cap_applied = raw_score > DEVICE_RISK_SCORE_CAP
    score = min(raw_score, DEVICE_RISK_SCORE_CAP)

    # Final-score counterfactual:
    # what the final score would be if this factor were removed.
    for item in breakdown:
        impact = int(item.get("impact", 0) or 0)
        item["scoreWithoutFactor"] = min(
            max(raw_score - impact, 0),
            DEVICE_RISK_SCORE_CAP
        )
        item["remediationImpact"] = -impact

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    # Reasons are sorted only for presentation.
    reasons.sort(
        key=lambda reason: reason["severity"],
        reverse=True
    )

    for reason in reasons:
        reason.pop("severity", None)

    # Actual score contributions remain traceable.
    breakdown.sort(
        key=lambda item: item["impact"],
        reverse=True
    )

    total_breakdown_impact = sum(
        int(item.get("impact", 0))
        for item in breakdown
    )

    score_reconciliation = (
        "PASS"
        if raw_score == total_breakdown_impact
        else "CHECK"
    )

    return {
        "score": score,
        "rawScore": raw_score,
        "scoreCapApplied": score_cap_applied,
        "scoreCap": DEVICE_RISK_SCORE_CAP,
        "level": level,
        "reasons": reasons,
        "breakdown": breakdown,
        "reconciliation": score_reconciliation,
        "explainability": {
            "engine": {
                "name": "Device Risk Rule Engine",
                "version": DEVICE_RISK_ENGINE_VERSION,
                "explainabilityVersion": DEVICE_RISK_EXPLAINABILITY_VERSION
            },
            "method": {
                "type": "Deterministic device risk rule engine",
                "formula": "min(sum(applicable rule impacts), scoreCap)",
                "scoreCap": 100
            },
            "ruleCatalog": DEVICE_RISK_RULES,
            "calculation": {
                "rawScore": raw_score,
                "totalBreakdownImpact": total_breakdown_impact,
                "finalScore": score,
                "scoreCapApplied": score_cap_applied,
                "factorCount": len(breakdown),
                "evidenceComplete": all(
                    item.get("source")
                    and item.get("sourceField")
                    and item.get("observedValue") is not None
                    for item in breakdown
                )
            }
        }
    }
