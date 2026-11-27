from datetime import datetime
import json

from ai_engine import ai_engine
from ai_feedback import get_learning_examples


def ai_analyze_device(
    device,
    baseline_analysis,
    feedback_examples
):
    prompt = f"""
You are a Network Security AI.

Analyze the following network device.

DEVICE DATA:
{json.dumps(device, indent=2)}

BASELINE DEVICE ANALYSIS:
{json.dumps(baseline_analysis, indent=2)}

HISTORICAL HUMAN FEEDBACK:
{json.dumps(feedback_examples or [], indent=2)}

Instructions:

1. Use the current device evidence as the primary source.
2. Use the baseline analysis as supporting information.
3. Use historical human feedback only as guidance.
4. Do not blindly copy previous feedback.
5. Return JSON only.

Return these fields:

riskScore
riskLevel
confidence
category
suspicious
summary
reasoning
recommendations
"""

    response = ai_engine.ask_device(
        device,
        baseline_analysis,
        feedback_examples
    )

    analysis = json.loads(
        response
    )

    if not isinstance(analysis, dict):
        raise ValueError(
            "Device AI response must be a JSON object."
        )

    return analysis

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

    confidence = min(
        95,
        70 + len(reasons) * 5
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


    # AI Confidence Explanation

    confidence_explanation = []

    if device.get("manufacturer"):
        confidence_explanation.append({
            "factor": "Manufacturer Identified",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("deviceType"):
        confidence_explanation.append({
            "factor": "Device Type Identified",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("operatingSystem"):
        confidence_explanation.append({
            "factor": "Operating System Identified",
            "status": "✔",
            "impact": "+5%"
        })
    else:
        confidence_explanation.append({
            "factor": "Operating System Unknown",
            "status": "✖",
            "impact": "-5%"
        })

    if device.get("httpBannerDetected"):
        confidence_explanation.append({
            "factor": "HTTP Banner Collected",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("sshBannerDetected"):
        confidence_explanation.append({
            "factor": "SSH Banner Collected",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("snmpEnabled"):
        confidence_explanation.append({
            "factor": "SNMP Information Available",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("lldpSystemName"):
        confidence_explanation.append({
            "factor": "LLDP Information Available",
            "status": "✔",
            "impact": "+5%"
        })

    if device.get("cdpDeviceId"):
        confidence_explanation.append({
            "factor": "CDP Information Available",
            "status": "✔",
            "impact": "+5%"
        })

    confidence_summary = (
        f"AI confidence is {confidence}% because the analysis is based on "
        f"{len(confidence_explanation)} verified network attributes collected "
        f"during discovery and protocol analysis."
    )

    
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

    # -------------------------------------------------
    # EXISTING DEVICE ANALYSIS CODE
    # -------------------------------------------------

    baseline_analysis = {

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
        "analysisTime": analysis_time,
        "analyzedAt": analysis_date,
        "securityTimeline": security_timeline,
        "threatPrediction": threat_prediction,
        "riskPrioritization": risk_prioritization,
        "securityScoreBreakdown": security_score_breakdown,
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

    # -------------------------------------------------
    # PHASE C
    # -------------------------------------------------

    try:

        feedback_examples = get_learning_examples(
            20,
            "device"
        )

    except Exception:

        feedback_examples = []

    ai_result = ai_analyze_device(
        device,
        baseline_analysis,
        feedback_examples
    )

    if not isinstance(ai_result, dict):
        raise ValueError(
            "Device AI response must be a JSON object."
        )

    final_analysis = dict(
        baseline_analysis
    )

    final_analysis.update(
        ai_result
    )

    if ai_result.get("summary"):
        final_analysis["ai"] = (
            ai_result["summary"]
        )

    return final_analysis