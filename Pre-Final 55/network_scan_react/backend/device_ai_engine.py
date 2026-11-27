from datetime import datetime
from device_risk import DEVICE_RISK_RULES


def analyze_device(device):

    score = device.get("deviceRiskScore", 0)
    reasons = [
        reason.get("text", "")
        for reason in device.get("deviceRiskReasons", [])
    ]
    recommendations = [
        {
            "icon": reason.get("icon", "💡"),
            "text": reason.get("recommendation", "")
        }
        for reason in device.get("deviceRiskReasons", [])
        if reason.get("recommendation")
    ]

    # Attack Surface
    attack_surface = []

    if device.get("httpBannerDetected"):
        attack_surface.append("🌐 HTTP")

    if device.get("httpScheme") == "HTTPS":
        attack_surface.append("🔒 HTTPS")

    if device.get("snmpEnabled"):
        attack_surface.append("📡 SNMP")

    if device.get("sshBannerDetected"):
        attack_surface.append("🔑 SSH")

    open_ports = str(device.get("openPorts", "")).upper()

    ports = {
        port.strip()
        for port in str(device.get("openPorts", "")).split(",")
        if port.strip()
    }

    if "21" in ports:
        attack_surface.append("📁 FTP")

    if "23" in ports:
        attack_surface.append("⚠️ Telnet")

    if "1900" in open_ports or "UPNP" in str(device.get("discoverySource", "")).upper():
        attack_surface.append("📺 UPnP")

    # Risk Score
    risk = device.get("deviceRiskLevel", "Low")

    # Discovery Protocols
    discovery = device.get("discoverySource", "")

    if discovery:
        reasons.append(
            f"Device discovered using {discovery}."
        )


    # Default Message
    if not reasons:
        reasons.append(
            "No significant security findings detected."
        )

    if not recommendations:
        recommendations.append(
            "Continue periodic security monitoring."
        )


    # Final Result

    hostname = device.get("hostname") or device.get("ip") or "Unknown Device"

    top_findings = ", ".join(reasons[:3])

    if top_findings:
        summary = (
            f"{hostname} is classified as a {risk} risk device "
            f"(Score: {score}/100). "
            f"Primary findings: {top_findings}."
        )
    else:
        summary = (
            f"{hostname} is classified as a {risk} risk device "
            f"(Score: {score}/100). "
            f"No significant security findings were detected."
        )


    # Device Security Grade
    if score >= 80:
        security_grade = "F"
    elif score >= 60:
        security_grade = "C"
    elif score >= 40:
        security_grade = "B"
    elif score >= 20:
        security_grade = "A"
    else:
        security_grade = "A+"

    now = datetime.now()

    analysis_time = now.strftime("%H:%M:%S")

    analysis_date = now.strftime("%d-%b-%Y %H:%M:%S")

    # AI Security Timeline

    security_timeline = [

        {
            "icon": "🛰️",
            "event": "Device Discovered",
            "time": analysis_date
        },

        {
            "icon": "🧠",
            "event": "AI Risk Analysis Completed",
            "time": analysis_date
        },

        {
            "icon": "🛡️",
            "event": "Security Assessment Generated",
            "time": analysis_date
        },

        {
            "icon": "📅",
            "event": "Next Recommended Review",
            "time": "Next Network Scan"
        }

    ]

    # Executive Security Summary
    if score >= 80:
        executive_summary = (
            "Immediate action required. This device has multiple high-risk "
            "security findings and should be reviewed without delay."
        )
    elif score >= 60:
        executive_summary = (
            "High-risk configuration detected. Review exposed services and "
            "strengthen device security."
        )
    elif score >= 40:
        executive_summary = (
            "Moderate security posture. Some improvements are recommended."
        )
    else:
        executive_summary = (
            "Good security posture. Continue routine monitoring and maintenance."
        )


    # AI Risk Indicators
    risk_indicators = []

    if device.get("httpBannerDetected"):
        risk_indicators.append("🌐 HTTP Interface")

    if device.get("snmpEnabled"):
        risk_indicators.append("📡 SNMP Enabled")

    if device.get("sshBannerDetected"):
        risk_indicators.append("🔑 SSH Enabled")

    if "UPNP" in str(device.get("discoverySource", "")).upper():
        risk_indicators.append("📺 UPnP Available")

    if not device.get("operatingSystem"):
        risk_indicators.append("⚠️ Unknown Operating System")

    # Security Posture
    if score >= 80:
        security_posture = "🔴 Critical - Immediate remediation required."
    elif score >= 60:
        security_posture = "🟠 High - Review exposed services and harden the device."
    elif score >= 40:
        security_posture = "🟡 Moderate - Improve security configuration."
    else:
        security_posture = "🟢 Healthy - Continue routine monitoring."

    # AI Device Fingerprinting
    fingerprint = "Unknown Network Device"

    if device.get("category", "").lower() == "gateway":
        fingerprint = "Internet Gateway"

    elif "router" in str(device.get("deviceType", "")).lower():
        fingerprint = "Residential WiFi Router"

    elif "switch" in str(device.get("deviceType", "")).lower():
        fingerprint = "Managed Ethernet Switch"

    elif "access point" in str(device.get("deviceType", "")).lower():
        fingerprint = "Wireless Access Point"

    elif "printer" in str(device.get("deviceType", "")).lower():
        fingerprint = "Network Printer"

    elif "camera" in str(device.get("deviceType", "")).lower():
        fingerprint = "IP Surveillance Camera"

    elif "android" in str(device.get("operatingSystem", "")).lower():
        fingerprint = "Android Smart Device"

    elif "windows" in str(device.get("operatingSystem", "")).lower():
        fingerprint = "Windows Computer"


    # AI Network Role Detection

    network_role = "Unknown Endpoint"

    category = str(device.get("category", "")).lower()
    device_type = str(device.get("deviceType", "")).lower()
    connection = str(device.get("connectionType", "")).lower()
    discovery = str(device.get("discoverySource", "")).lower()

    if category == "gateway":
        network_role = "Internet Gateway"

    elif "router" in device_type:
        network_role = "Network Router"

    elif "switch" in device_type:
        network_role = "Layer-2 Switch"

    elif "access point" in device_type:
        network_role = "Wireless Access Point"

    elif "printer" in device_type:
        network_role = "Network Printer"

    elif "camera" in device_type:
        network_role = "IP Surveillance Camera"

    elif "windows" in str(device.get("operatingSystem", "")).lower():
        network_role = "Client Workstation"

    elif "android" in str(device.get("operatingSystem", "")).lower():
        network_role = "Mobile Endpoint"

    elif connection == "wireless":
        network_role = "Wireless Endpoint"

    elif connection == "wired":
        network_role = "Wired Endpoint"

    elif "upnp" in discovery:
        network_role = "UPnP Network Device"

    elif "mdns" in discovery:
        network_role = "mDNS Service Device"

    elif "netbios" in discovery:
        network_role = "NetBIOS Host"


    # AI Threat Prediction

    threat_prediction = []

    if score >= 80:
        threat_prediction.append({
            "severity": "Critical",
            "prediction": "High probability of device compromise if not remediated."
        })

    elif score >= 60:
        threat_prediction.append({
            "severity": "High",
            "prediction": "Device may become vulnerable to targeted attacks."
        })

    elif score >= 40:
        threat_prediction.append({
            "severity": "Medium",
            "prediction": "Security posture may degrade if configuration is not improved."
        })

    else:
        threat_prediction.append({
            "severity": "Low",
            "prediction": "No immediate threat predicted. Continue routine monitoring."
        })

    if device.get("httpBannerDetected"):
        threat_prediction.append({
            "severity": "Medium",
            "prediction": "Web management interface could be targeted for credential attacks."
        })

    if device.get("snmpEnabled"):
        threat_prediction.append({
            "severity": "Medium",
            "prediction": "SNMP exposure may reveal sensitive network information."
        })

    if device.get("sshBannerDetected"):
        threat_prediction.append({
            "severity": "Low",
            "prediction": "SSH service should be protected using strong authentication."
        })

    if "23" in ports:
        threat_prediction.append({
            "severity": "Critical",
            "prediction": "Telnet service significantly increases future compromise risk."
        })

    if "21" in ports:
        threat_prediction.append({
            "severity": "High",
            "prediction": "FTP service may expose credentials unless secured."
        })


    # AI Risk Prioritization

    risk_prioritization = []

    if score >= 80:
        risk_prioritization.append({
            "priority": 1,
            "severity": "Critical",
            "title": "Immediate Security Remediation",
            "reason": "Device has a critical risk score.",
            "action": "Isolate the device and investigate immediately."
        })

    if "23" in ports:
        risk_prioritization.append({
            "priority": 2,
            "severity": "Critical",
            "title": "Disable Telnet",
            "reason": "Telnet transmits credentials in plain text.",
            "action": "Disable Telnet and migrate to SSH."
        })

    if device.get("httpBannerDetected"):
        risk_prioritization.append({
            "priority": 3,
            "severity": "High",
            "title": "Secure Web Interface",
            "reason": "HTTP management interface detected.",
            "action": "Redirect management traffic to HTTPS."
        })

    if device.get("snmpEnabled"):
        risk_prioritization.append({
            "priority": 4,
            "severity": "High",
            "title": "Review SNMP Configuration",
            "reason": "SNMP service is exposed.",
            "action": "Use SNMPv3 and restrict access."
        })

    if "21" in ports:
        risk_prioritization.append({
            "priority": 5,
            "severity": "Medium",
            "title": "Secure FTP Service",
            "reason": "FTP may expose credentials.",
            "action": "Replace FTP with SFTP or FTPS."
        })

    if device.get("sshBannerDetected"):
        risk_prioritization.append({
            "priority": 6,
            "severity": "Low",
            "title": "Harden SSH",
            "reason": "SSH service is available.",
            "action": "Allow key-based authentication only."
        })

    if not risk_prioritization:
        risk_prioritization.append({
            "priority": 1,
            "severity": "Low",
            "title": "Routine Monitoring",
            "reason": "No significant security issues detected.",
            "action": "Continue periodic security monitoring."
        })

    risk_prioritization.sort(key=lambda x: x["priority"])


    # AI Security Score Breakdown
    # Uses the actual breakdown generated by the device risk engine.

    security_score_breakdown = device.get(
        "deviceRiskBreakdown",
        []
    )

    if not isinstance(security_score_breakdown, list):
        security_score_breakdown = []

    # The scanner may not yet copy rawScore onto the device object.
    # Derive it from the authoritative risk breakdown when necessary.
    breakdown_raw_score = sum(
        int(item.get("impact", 0) or 0)
        for item in security_score_breakdown
        if isinstance(item, dict)
    )

    raw_score = device.get(
        "deviceRiskRawScore",
        breakdown_raw_score if breakdown_raw_score else score
    )

    score_cap_applied = device.get(
        "deviceRiskScoreCapApplied",
        int(raw_score or 0) > int(score or 0)
    )


    # AI Confidence Explanation
    #
    # Confidence is derived from the same evidence that is displayed
    # below.  This keeps the displayed confidence traceable instead of
    # using the previous "number of reasons" shortcut.

    confidence_explanation = []

    confidence_evidence = [
        (
            "Manufacturer Identified",
            bool(device.get("manufacturer")),
            "manufacturer",
            "device_discovery/OUI lookup",
            5
        ),
        (
            "Device Type Identified",
            bool(device.get("deviceType")),
            "deviceType",
            "device_fingerprinting",
            5
        ),
        (
            "Operating System Identified",
            bool(
                device.get("operatingSystem")
                and str(device.get("operatingSystem")).lower()
                not in ("unknown", "n/a")
            ),
            "operatingSystem",
            "device_fingerprinting",
            5
        ),
        (
            "HTTP Banner Collected",
            bool(device.get("httpBannerDetected")),
            "httpBannerDetected",
            "http_banner_scan",
            5
        ),
        (
            "SSH Banner Collected",
            bool(device.get("sshBannerDetected")),
            "sshBannerDetected",
            "ssh_banner_scan",
            5
        ),
        (
            "SNMP Information Available",
            bool(device.get("snmpEnabled")),
            "snmpEnabled",
            "snmp_scan",
            5
        ),
        (
            "LLDP Information Available",
            bool(device.get("lldpSystemName")),
            "lldpSystemName",
            "lldp_scan",
            5
        ),
        (
            "CDP Information Available",
            bool(device.get("cdpDeviceId")),
            "cdpDeviceId",
            "cdp_scan",
            5
        ),
        (
            "Open Ports Identified",
            bool(
                str(device.get("openPorts", "")).strip()
            ),
            "openPorts",
            "nmap",
            5
        ),
        (
            "Services Identified",
            bool(
                str(device.get("services", "")).strip()
            ),
            "services",
            "nmap/service_detection",
            5
        )
    ]

    # Base confidence represents that a device analysis was performed.
    confidence_base = 50

    for (
        factor,
        available,
        source_field,
        source,
        weight
    ) in confidence_evidence:

        confidence_explanation.append({
            "factor": factor,
            "status": "✔" if available else "✖",
            "impact": f"+{weight}%" if available else "+0%",
            "weight": weight,
            "source": source,
            "sourceField": source_field,
            "evidenceAvailable": available,
            "observedValue": device.get(source_field)
        })

    confidence = min(
        100,
        confidence_base
        + sum(
            item["weight"]
            for item in confidence_explanation
            if item["evidenceAvailable"]
        )
    )

    confidence_summary = (
        f"AI confidence is {confidence}% based on "
        f"{sum(1 for item in confidence_explanation if item['evidenceAvailable'])} "
        f"available evidence sources out of "
        f"{len(confidence_explanation)} evaluated evidence sources. "
        f"Base analysis confidence is {confidence_base}%."
    )

    confidence_available_weight = sum(
        int(item.get("weight", 0) or 0)
        for item in confidence_explanation
        if item.get("evidenceAvailable")
    )

    confidence_total_weight = sum(
        int(item.get("weight", 0) or 0)
        for item in confidence_explanation
    )

    confidence_calculation = {
        "baseScore": confidence_base,
        "availableEvidenceWeight": confidence_available_weight,
        "totalEvidenceWeight": confidence_total_weight,
        "availableEvidenceCount": sum(
            1
            for item in confidence_explanation
            if item.get("evidenceAvailable")
        ),
        "totalEvidenceCount": len(confidence_explanation),
        "formula": "baseScore + sum(weight for available evidence)",
        "maxScore": 100,
        "finalScore": confidence
    }

    # ---------------------------------------------------------
    # Phase C - Complete AI Explainability
    # ---------------------------------------------------------

    explainability_factors = []

    for item in security_score_breakdown:

        if not isinstance(item, dict):
            continue

        impact = int(item.get("impact", 0) or 0)

        explainability_factors.append({
            "ruleId": item.get(
                "ruleId",
                "UNKNOWN-RULE"
            ),
            "factor": item.get(
                "factor",
                "Unknown"
            ),
            "impact": impact,
            "scoreBefore": item.get(
                "scoreBefore"
            ),
            "scoreAfter": item.get(
                "scoreAfter"
            ),
            "scoreWithoutFactor": min(
                max(int(raw_score or 0) - impact, 0),
                100
            ),
            "remediationImpact": -impact,
            "severity": item.get(
                "severity",
                "Unknown"
            ),
            "description": item.get(
                "description",
                ""
            ),
            "recommendation": item.get(
                "recommendation",
                ""
            ),
            "source": item.get(
                "source",
                "device_risk_engine"
            ),
            "role": item.get(
                "role",
                "Actual device risk-score contribution"
            ),
            "sourceField": item.get(
                "sourceField",
                ""
            ),
            "observedValue": item.get(
                "observedValue"
            )
        })

    total_factor_impact = sum(
        int(item.get("impact", 0) or 0)
        for item in explainability_factors
    )

    score_reconciliation = (
        "PASS"
        if total_factor_impact == int(raw_score or 0)
        else "CHECK"
    )

    factor_evidence_complete = all(
        item.get("source")
        and item.get("sourceField")
        and item.get("observedValue") is not None
        for item in explainability_factors
    )

    explainability_limitations = [
        "The explanation reflects the evidence and deterministic rules available during the current device analysis.",
        "The risk score is a rule-based security attention score and does not by itself establish malicious activity.",
        "A capped score can be lower than the raw sum of applicable rule impacts.",
        "Confidence represents evidence availability, not certainty that a security finding is correct.",
        "Device fingerprinting quality depends on the discovery protocols and services that respond."
    ]

    if not device.get("manufacturer"):
        explainability_limitations.append(
            "Manufacturer evidence was unavailable."
        )

    if not device.get("operatingSystem"):
        explainability_limitations.append(
            "Operating-system evidence was unavailable."
        )

    if not device.get("httpBannerDetected"):
        explainability_limitations.append(
            "HTTP banner evidence was unavailable."
        )

    if not device.get("sshBannerDetected"):
        explainability_limitations.append(
            "SSH banner evidence was unavailable."
        )

    if not factor_evidence_complete:
        explainability_limitations.append(
            "One or more applied risk factors are missing complete provenance "
            "(source, source field, or observed value)."
        )

    if score_reconciliation != "PASS":
        explainability_limitations.append(
            "The displayed factor impacts do not reconcile with the raw score."
        )

    explainability = {
        "engine": {
            "name": "Rule-Based AI Engine",
            "version": "device-ai-v2",
            "explainabilityVersion": "1.1"
        },

        "ruleCatalog": device.get(
            "deviceRiskRuleCatalog",
            DEVICE_RISK_RULES
        ),

        "summary": (
            f"The device received a {risk} risk classification with a "
            f"final score of {score}/100. The decision is traceable to "
            f"{len(explainability_factors)} applicable security rule(s) "
            f"and the evidence recorded for each rule."
        ),

        "method": {
            "type": "Deterministic device risk rule engine",
            "formula": "min(sum(applicable rule impacts), 100)",
            "scoreCap": 100,
            "decisionSource": "device_risk_engine"
        },

        "decision": {
            "riskScore": score,
            "riskLevel": risk,
            "securityGrade": security_grade,
            "confidence": confidence
        },

        "scoreExplanation": {
            "rawScore": raw_score,
            "finalScore": score,
            "scoreCap": 100,
            "scoreCapApplied": bool(score_cap_applied),
            "totalFactorImpact": total_factor_impact,
            "factorCount": len(explainability_factors),
            "reconciliation": score_reconciliation,
            "evidenceComplete": factor_evidence_complete,
            "rawScoreReconciliation": (
                f"{raw_score} = {total_factor_impact}"
            ),
            "riskLevelThresholds": {
                "Critical": "score >= 80",
                "High": "score >= 60",
                "Medium": "score >= 40",
                "Low": "score < 40"
            },
            "formulaTrace": (
                "Final score = min(raw score, score cap); "
                "raw score = sum(applicable rule impacts)"
            )
        },

        "factors": explainability_factors,

        "confidence": {
            "score": confidence,
            "baseScore": confidence_base,
            "summary": confidence_summary,
            "calculation": confidence_calculation,
            "evidenceComplete": (confidence_available_weight == confidence_total_weight),
            "factors": confidence_explanation
        },

        "observations": [
            {
                "name": "Risk Level",
                "value": risk,
                "detail": (
                    f"Final device risk score is {score}/100."
                )
            },
            {
                "name": "Applicable Risk Rules",
                "value": len(explainability_factors),
                "detail": (
                    f"{len(explainability_factors)} rule(s) contributed "
                    f"to the current raw score."
                )
            },
            {
                "name": "Evidence Sources",
                "value": sum(
                    1
                    for item in confidence_explanation
                    if item["evidenceAvailable"]
                ),
                "detail": (
                    "Evidence sources available for the current analysis."
                )
            }
        ],

        "recommendations": [
            {
                "ruleId": item.get("ruleId"),
                "factor": item.get("factor"),
                "severity": item.get("severity"),
                "impact": item.get("impact"),
                "observedValue": item.get("observedValue"),
                "action": item.get("recommendation")
            }
            for item in explainability_factors
            if item.get("recommendation")
        ],

        "limitations": explainability_limitations,

        "analysis": {
            "analysisTime": analysis_time,
            "analyzedAt": analysis_date
        }
    }

    # Phase D1 - AI Network Topology Intelligence

    topology_role = device.get("topologyRole", "Endpoint")

    topology_parent = (
        device.get("topologyParentName")
        or "None"
    )

    topology_level = device.get("topologyLevel", 0)

    topology_children = device.get("childCount", 0)

    topology_connection = (
        device.get("parentLinkType")
        or device.get("connectionType")
        or "Unknown"
    )

    topology_confidence = (
        device.get("linkConfidence")
        or "Unknown"
    )

    topology_path = (
        device.get("topologyPath")
        or topology_role
    )

    if topology_role == "Gateway":

        topology_summary = (
            f"This device is acting as the primary network gateway. "
            f"It currently has {topology_children} directly connected device(s). "
            f"Topology confidence is {topology_confidence}."
        )

    elif topology_role == "Switch":

        topology_summary = (
            f"This device operates as a network switch connecting "
            f"{topology_children} downstream device(s). "
            f"Topology confidence is {topology_confidence}."
        )

    elif topology_role == "Access Point":

        topology_summary = (
            f"This wireless access point currently serves "
            f"{topology_children} connected device(s). "
            f"Topology confidence is {topology_confidence}."
        )

    else:

        topology_summary = (
            f"This endpoint is connected through "
            f"{topology_parent} using {topology_connection}. "
            f"The inferred network path confidence is "
            f"{topology_confidence}."
        )



    # Phase D2 - AI Device Relationship Analysis

    relationship = (
        "Root Device"
        if topology_level == 0
        else "Child Device"
    )

    sibling_count = max(
        0,
        topology_children - 1
    )

    if topology_level == 0:
        network_position = "Core Layer"

    elif topology_level == 1:
        network_position = "Distribution Layer"

    else:
        network_position = "Access Layer"

    gateway_distance = (
        f"{topology_level} Hop"
        if topology_level == 1
        else f"{topology_level} Hops"
    )

    if topology_level == 0:

        relationship_summary = (
            "This device is the root of the discovered network topology "
            "and acts as the communication point for downstream devices."
        )

    else:

        relationship_summary = (
            f"This device is connected to {topology_parent}. "
            f"It is located in the {network_position} of the network. "
            f"Traffic reaches the gateway through approximately "
            f"{gateway_distance.lower()}."
        )



    # Phase D3 - AI Communication Intelligence

    communication_mode = (
        "Encrypted"
        if str(device.get("httpScheme", "")).upper() == "HTTPS"
        else "Unencrypted"
    )

    primary_protocol = (
        device.get("primaryDiscoveryProtocol")
        or "Unknown"
    )

    exposed_services = (
        device.get("services")
        or "None Detected"
    )

    communication_pattern = (
        "Infrastructure Communication"
        if network_role in ["Gateway", "Switch", "Access Point"]
        else "Endpoint Communication"
    )

    communication_summary = (
        f"This device primarily communicates using "
        f"{primary_protocol}. "
        f"The communication is {communication_mode.lower()}. "
        f"Detected services: {exposed_services}. "
        f"It follows a typical {communication_pattern.lower()} pattern."
    )


    # Phase D8 - AI Network Health Assessment

    health_score = 100

    if score >= 80:
        health_score -= 40
    elif score >= 60:
        health_score -= 25
    elif score >= 40:
        health_score -= 15

    if not device.get("active", True):
        health_score -= 25

    if not device.get("operatingSystem"):
        health_score -= 5

    if not device.get("manufacturer"):
        health_score -= 5

    if not device.get("responseTime"):
        health_score -= 5

    health_score = max(0, min(100, health_score))

    if health_score >= 90:
        overall_health = "Excellent"
    elif health_score >= 75:
        overall_health = "Good"
    elif health_score >= 60:
        overall_health = "Fair"
    else:
        overall_health = "Poor"

    availability = (
        "Online"
        if device.get("active", False)
        else "Offline"
    )

    response_performance = (
        "Measured"
        if device.get("responseTime")
        else "Unknown"
    )

    service_availability = (
        "Available"
        if device.get("services")
        else "No Services Detected"
    )

    protocol_coverage = (
        device.get("discoverySource")
        or "Unknown"
    )

    discovery_quality = (
        "High"
        if confidence >= 90
        else "Medium"
        if confidence >= 75
        else "Low"
    )

    health_summary = (
        f"The device health is {overall_health.lower()} "
        f"with a health score of {health_score}/100. "
        f"The device is currently {availability.lower()} "
        f"and discovery quality is {discovery_quality.lower()}."
    )


    # Phase D9 - AI Device Lifecycle Assessment

    if device.get("active", False):
        lifecycle_status = "Operational"
    else:
        lifecycle_status = "Inactive"

    lifecycle_stage = (
        "Managed Infrastructure"
        if network_role in [
            "Internet Gateway",
            "Layer-2 Switch",
            "Wireless Access Point"
        ]
        else "Endpoint Device"
    )

    monitoring_recommendation = (
        "Routine Monitoring"
        if health_score >= 80
        else "Frequent Monitoring"
    )

    lifecycle_summary = (
        f"The device is currently {lifecycle_status.lower()} "
        f"and classified as a {lifecycle_stage.lower()}. "
        f"The recommended monitoring strategy is "
        f"{monitoring_recommendation.lower()}."
    )

    return {

        "ai": summary,
        "executiveSummary": executive_summary,
        "aiModel": "Rule-Based AI Engine",
        "deviceType": device.get("deviceType", "-"),
        "fingerprint": fingerprint,
        "networkRole": network_role,
        "category": device.get("category", "-"),
        "riskScore": score,
        "riskLevel": risk,
        "riskCategory": "Network Device Security",
        "securityGrade": security_grade,
        "attackSurface": attack_surface,
        "riskIndicators": risk_indicators,
        "securityPosture": security_posture,
        "confidence": confidence,
        "confidenceExplanation": confidence_explanation,
        "confidenceSummary": confidence_summary,
        "scoreExplanation": explainability["scoreExplanation"],
        "analysisTime": analysis_time,
        "analyzedAt": analysis_date,
        "securityTimeline": security_timeline,
        "threatPrediction": threat_prediction,
        "riskPrioritization": risk_prioritization,
        "securityScoreBreakdown": security_score_breakdown,
        "deviceRiskRawScore": raw_score,
        "deviceRiskScoreCapApplied": score_cap_applied,
        "deviceRiskScoreCap": explainability["scoreExplanation"].get(
            "scoreCap",
            100
        ),
        "deviceRiskExplainabilityVersion": explainability["engine"].get(
            "explainabilityVersion",
            "1.1"
        ),
        "explainability": explainability,
        "operatingSystem": device.get("operatingSystem", "-"),
        "manufacturer": device.get("manufacturer", "-"),
        "model": device.get("model", "-"),
        "ip": device.get("ip", ""),
        "mac": device.get("mac", ""),
        "reasons": reasons,
        "recommendations": recommendations,

        "topologyIntelligence": {

            "role": topology_role,
            "parent": topology_parent,
            "level": topology_level,
            "children": topology_children,
            "connection": topology_connection,
            "confidence": topology_confidence,
            "path": topology_path,
            "summary": topology_summary

        },

        "relationshipAnalysis": {

            "relationship": relationship,
            "parentDevice": topology_parent,
            "networkPosition": network_position,
            "gatewayDistance": gateway_distance,
            "connectedThrough": topology_connection,
            "siblingDevices": sibling_count,
            "summary": relationship_summary

        },

        "communicationIntelligence": {

            "primaryProtocol": primary_protocol,
            "communicationMode": communication_mode,
            "communicationPattern": communication_pattern,
            "services": exposed_services,
            "summary": communication_summary

        },

        "networkHealthAssessment": {

            "overallHealth": overall_health,
            "healthScore": health_score,
            "availability": availability,
            "responsePerformance": response_performance,
            "serviceAvailability": service_availability,
            "protocolCoverage": protocol_coverage,
            "discoveryQuality": discovery_quality,
            "summary": health_summary

        },

        "deviceLifecycleAssessment": {

            "lifecycleStatus": lifecycle_status,
            "lifecycleStage": lifecycle_stage,
            "monitoringRecommendation": monitoring_recommendation,
            "summary": lifecycle_summary

        }
    }