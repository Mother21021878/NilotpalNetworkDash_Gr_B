import json
import os

from traffic_analysis import analyse_pcap
from risk_analysis import analyse_risk

TRAFFIC_HISTORY = []
NETWORK_BASELINE_HISTORY = []
SCAN_CONTEXT = {}

def initialize_scan_context(
    devices,
    traffic=None,
    risk=None
):
    """
    Initialize scan context for one network scan.
    """

    global SCAN_CONTEXT

    if traffic is None:
        traffic = analyse_pcap()

    if risk is None:
        risk = analyse_risk()

    SCAN_CONTEXT = {

        "devices":
            devices,

        "traffic":
            traffic or {},

        "risk":
            risk or {},

        "baseline_updated":
            False,

        "current_efficiency_score":
            None
    }

def analyze_network_health(devices):
    """
    Overall Network Health Score.
    """
    initialize_scan_context(devices)

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    risk = SCAN_CONTEXT["risk"]

    stability_info = analyze_network_stability()

    reliability_info = analyze_network_reliability(devices)

    availability_info = analyze_network_availability(devices)

    performance_info = analyze_network_performance()

    bandwidth_info = analyze_bandwidth_utilization()

    traffic_load_info = analyze_traffic_load()

    traffic_trend_info = analyze_traffic_trend()

    peak_traffic_info = analyze_peak_traffic()

    traffic_burst_info = analyze_traffic_burst()

    traffic_congestion_info = analyze_traffic_congestion()

    traffic_quality_info = analyze_traffic_quality()

    protocol_distribution_info = analyze_protocol_distribution()

    protocol_risk_info = analyze_protocol_risk()

    protocol_health_info = analyze_protocol_health()

    protocol_anomaly_info = analyze_protocol_anomalies()

    protocol_security_info = analyze_protocol_security()

    traffic_pattern_info = analyze_traffic_pattern()

    network_utilization_info = analyze_network_utilization()

    network_activity_info = analyze_network_activity()

    network_behavior_info = analyze_network_behavior()

    communication_pattern_info = analyze_communication_pattern()

    network_efficiency_info = analyze_network_efficiency()

    network_baseline_info = analyze_network_baseline()

    behavior_anomaly_info = analyze_behavior_anomaly()

    behavior_intelligence_info = analyze_behavior_intelligence()

    network_intelligence_summary_info = analyze_network_intelligence_summary(devices)

    
    total_devices = len(devices)

    online_devices = sum(
        1
        for device in devices
        if device.get("active")
    )

    availability = (
        (online_devices / total_devices) * 100
        if total_devices
        else 0
    )

    packet_rate = traffic.get(
        "packetRate",
        0
    )

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    risk_score = risk.get(
        "riskScore",
        0
    )

    health_score = round(

        (
            availability
            + max(0, 100 - risk_score)
            + max(0, 100 - min(packet_rate / 10, 100))
            + max(0, 100 - min(throughput, 100))
        ) / 4,

        2
    )

    if health_score >= 90:
        status = "Excellent"

    elif health_score >= 75:
        status = "Good"

    elif health_score >= 50:
        status = "Fair"

    else:
        status = "Poor"

    
    return {

        "healthScore":
            health_score,

        "healthStatus":
            status,

        "networkAvailability":
            availability_info,

        "networkStability":
            stability_info,

        "networkReliability":
            reliability_info,

        "networkPerformance":
            performance_info,

        "bandwidthUtilization":
            bandwidth_info,

        "trafficLoad":
            traffic_load_info,

        "trafficTrend":
            traffic_trend_info,

        "peakTraffic":
            peak_traffic_info,

        "trafficBurst":
            traffic_burst_info,

        "trafficCongestion":
            traffic_congestion_info,

        "trafficQuality":
            traffic_quality_info,

        "protocolDistribution":
            protocol_distribution_info,

        "protocolRisk":
            protocol_risk_info,

        "protocolHealth":
            protocol_health_info,

        "protocolAnomalies":
            protocol_anomaly_info,

        "protocolSecurity":
            protocol_security_info,

        "trafficPattern":
            traffic_pattern_info,

        "networkUtilization":
            network_utilization_info,

        "networkActivity":
            network_activity_info,

        "networkBehavior":
            network_behavior_info,

        "communicationPattern":
            communication_pattern_info,

        "networkEfficiency":
            network_efficiency_info,

        "networkBaseline":
            network_baseline_info,

        "behaviorAnomaly":
            behavior_anomaly_info,

        "behaviorIntelligence":
            behavior_intelligence_info,

        "networkIntelligenceSummary":
            network_intelligence_summary_info,

        "trafficRisk":
            risk.get("riskLevel"),

        "packetRate":
            packet_rate,

        "throughputMbps":
            throughput
    }

def analyze_network_availability(devices):
    """
    Network Availability Analysis.
    """

    total_devices = len(devices)

    online_devices = sum(
        1
        for device in devices
        if device.get("active")
    )

    offline_devices = (
        total_devices - online_devices
    )

    availability = (
        (online_devices / total_devices) * 100
        if total_devices
        else 0
    )

    if availability >= 99:
        status = "Excellent"

    elif availability >= 95:
        status = "Healthy"

    elif availability >= 80:
        status = "Degraded"

    else:
        status = "Critical"

    return {

        "totalDevices":
            total_devices,

        "onlineDevices":
            online_devices,

        "offlineDevices":
            offline_devices,

        "availabilityPercentage":
            round(availability, 2),

        "availabilityStatus":
            status
    }

def analyze_network_stability():
    """
    Network Stability Analysis.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    risk = SCAN_CONTEXT["risk"]

    packet_rate = traffic.get(
        "packetRate",
        0
    )

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    risk_score = risk.get(
        "riskScore",
        0
    )

    stability_score = round(

        (
            max(0, 100 - min(packet_rate / 10, 100))
            +
            max(0, 100 - min(throughput, 100))
            +
            max(0, 100 - risk_score)
        ) / 3,

        2
    )

    if stability_score >= 90:
        status = "Excellent"

    elif stability_score >= 75:
        status = "Stable"

    elif stability_score >= 50:
        status = "Moderate"

    else:
        status = "Unstable"

    return {

        "stabilityScore":
            stability_score,

        "stabilityStatus":
            status,

        "packetRate":
            packet_rate,

        "throughputMbps":
            throughput,

        "riskScore":
            risk_score
    }

def analyze_network_reliability(devices):
    """
    Network Reliability Analysis.
    """

    availability = analyze_network_availability(devices)

    stability = analyze_network_stability()

    availability_score = availability.get(
        "availabilityPercentage",
        0
    )

    stability_score = stability.get(
        "stabilityScore",
        0
    )

    reliability_score = round(

        (
            availability_score
            + stability_score
        ) / 2,

        2
    )

    if reliability_score >= 90:
        status = "Highly Reliable"

    elif reliability_score >= 75:
        status = "Reliable"

    elif reliability_score >= 50:
        status = "Acceptable"

    else:
        status = "Unreliable"

    return {

        "reliabilityScore":
            reliability_score,

        "reliabilityStatus":
            status,

        "availabilityScore":
            availability_score,

        "stabilityScore":
            stability_score
    }

def analyze_network_performance():
    """
    Network Performance Index.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    stability = analyze_network_stability()

    packet_rate = traffic.get(
        "packetRate",
        0
    )

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    stability_score = stability.get(
        "stabilityScore",
        0
    )

    performance_score = round(

        (
            max(0, 100 - min(packet_rate / 10, 100))
            +
            max(0, 100 - min(throughput, 100))
            +
            stability_score
        ) / 3,

        2
    )

    if performance_score >= 90:
        status = "Excellent"

    elif performance_score >= 75:
        status = "Good"

    elif performance_score >= 50:
        status = "Average"

    else:
        status = "Poor"

    return {

        "performanceScore":
            performance_score,

        "performanceStatus":
            status,

        "packetRate":
            packet_rate,

        "throughputMbps":
            throughput,

        "stabilityScore":
            stability_score
    }

def analyze_bandwidth_utilization(link_speed_mbps=1000):
    """
    Bandwidth Utilization Analysis.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    utilization = round(

        (throughput / link_speed_mbps) * 100,

        2
    )

    utilization = min(
        utilization,
        100
    )

    if utilization >= 90:
        status = "Critical"

    elif utilization >= 70:
        status = "High"

    elif utilization >= 40:
        status = "Moderate"

    else:
        status = "Low"

    return {

        "linkSpeedMbps":
            link_speed_mbps,

        "throughputMbps":
            throughput,

        "bandwidthUtilization":
            utilization,

        "utilizationStatus":
            status
    }

def analyze_traffic_load():
    """
    Traffic Load Analysis.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    bandwidth = analyze_bandwidth_utilization()

    packet_rate = traffic.get(
        "packetRate",
        0
    )

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    utilization = bandwidth.get(
        "bandwidthUtilization",
        0
    )

    load_score = round(

        (
            min(packet_rate / 10, 100)
            +
            min(throughput, 100)
            +
            utilization
        ) / 3,

        2
    )

    if load_score >= 80:
        status = "Heavy"

    elif load_score >= 60:
        status = "High"

    elif load_score >= 30:
        status = "Moderate"

    else:
        status = "Light"

    return {

        "trafficLoadScore":
            load_score,

        "trafficLoadStatus":
            status,

        "packetRate":
            packet_rate,

        "throughputMbps":
            throughput,

        "bandwidthUtilization":
            utilization
    }

def analyze_traffic_trend():
    """
    Traffic Trend Analysis.
    """

    global TRAFFIC_HISTORY

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    TRAFFIC_HISTORY.append(
        throughput
    )

    if len(TRAFFIC_HISTORY) > 20:
        TRAFFIC_HISTORY.pop(0)

    if len(TRAFFIC_HISTORY) < 2:

        trend = "Stable"

        change = 0

    else:

        previous = TRAFFIC_HISTORY[-2]

        current = TRAFFIC_HISTORY[-1]

        change = round(
            current - previous,
            2
        )

        if change > 1:

            trend = "Increasing"

        elif change < -1:

            trend = "Decreasing"

        else:

            trend = "Stable"

    return {

        "currentThroughput":
            throughput,

        "throughputChange":
            change,

        "trafficTrend":
            trend,

        "samples":
            len(TRAFFIC_HISTORY)
    }

def analyze_peak_traffic():
    """
    Peak Traffic Detection.
    """

    global TRAFFIC_HISTORY

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    if not TRAFFIC_HISTORY:

        average = throughput

    else:

        average = round(

            sum(TRAFFIC_HISTORY)
            /
            len(TRAFFIC_HISTORY),

            2
        )

    if average == 0:

        peak_percentage = 0

    else:

        peak_percentage = round(

            (
                throughput
                /
                average
            ) * 100,

            2
        )

    if peak_percentage >= 150:

        status = "Peak"

    elif peak_percentage >= 120:

        status = "High"

    else:

        status = "Normal"

    return {

        "currentThroughput":
            throughput,

        "averageThroughput":
            average,

        "peakPercentage":
            peak_percentage,

        "peakStatus":
            status
    }

def analyze_traffic_burst():
    """
    Traffic Burst Detection.
    """

    global TRAFFIC_HISTORY

    if len(TRAFFIC_HISTORY) < 2:

        return {

            "burstDetected": False,

            "burstPercentage": 0,

            "burstStatus": "Insufficient Data"
        }

    previous = TRAFFIC_HISTORY[-2]

    current = TRAFFIC_HISTORY[-1]

    if previous == 0:

        burst_percentage = 0

    else:

        burst_percentage = round(

            (
                (current - previous)
                /
                previous
            ) * 100,

            2
        )

    burst_detected = burst_percentage >= 30

    if burst_percentage >= 75:

        status = "Severe"

    elif burst_percentage >= 50:

        status = "High"

    elif burst_percentage >= 30:

        status = "Moderate"

    else:

        status = "Normal"

    return {

        "burstDetected":
            burst_detected,

        "burstPercentage":
            burst_percentage,

        "burstStatus":
            status,

        "previousThroughput":
            previous,

        "currentThroughput":
            current
    }

def analyze_traffic_congestion():
    """
    Traffic Congestion Analysis.
    """

    bandwidth = analyze_bandwidth_utilization()

    traffic_load = analyze_traffic_load()

    traffic_burst = analyze_traffic_burst()

    utilization = bandwidth.get(
        "bandwidthUtilization",
        0
    )

    load_score = traffic_load.get(
        "trafficLoadScore",
        0
    )

    burst_detected = traffic_burst.get(
        "burstDetected",
        False
    )

    congestion_score = round(

        (
            utilization
            +
            load_score
            +
            (100 if burst_detected else 0)
        ) / 3,

        2
    )

    if congestion_score >= 80:

        status = "Severe"

    elif congestion_score >= 60:

        status = "High"

    elif congestion_score >= 40:

        status = "Moderate"

    else:

        status = "Low"

    return {

        "congestionScore":
            congestion_score,

        "congestionStatus":
            status,

        "bandwidthUtilization":
            utilization,

        "trafficLoadScore":
            load_score,

        "burstDetected":
            burst_detected
    }

def analyze_traffic_quality():
    """
    Traffic Quality Index (TQI).
    """

    stability = analyze_network_stability()

    congestion = analyze_traffic_congestion()

    traffic_load = analyze_traffic_load()

    traffic_burst = analyze_traffic_burst()

    stability_score = stability.get(
        "stabilityScore",
        0
    )

    congestion_score = congestion.get(
        "congestionScore",
        0
    )

    load_score = traffic_load.get(
        "trafficLoadScore",
        0
    )

    burst_detected = traffic_burst.get(
        "burstDetected",
        False
    )

    quality_score = round(

        (
            stability_score
            +
            (100 - congestion_score)
            +
            (100 - load_score)
            +
            (0 if burst_detected else 100)
        ) / 4,

        2
    )

    if quality_score >= 90:

        status = "Excellent"

    elif quality_score >= 75:

        status = "Good"

    elif quality_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "trafficQualityScore":
            quality_score,

        "trafficQualityStatus":
            status,

        "stabilityScore":
            stability_score,

        "congestionScore":
            congestion_score,

        "trafficLoadScore":
            load_score,

        "burstDetected":
            burst_detected
    }

def analyze_protocol_distribution():
    """
    Protocol Distribution Analysis.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    protocol_stats = traffic.get(
        "protocolStats",
        {}
    )

    total_packets = sum(
        protocol_stats.values()
    )

    protocol_distribution = {}

    if total_packets > 0:

        for protocol, count in protocol_stats.items():

            protocol_distribution[protocol] = round(

                (count / total_packets) * 100,

                2
            )

    return {

        "totalPackets":
            total_packets,

        "protocolDistribution":
            protocol_distribution
    }

def analyze_protocol_risk():
    """
    Protocol Risk Analysis.
    """

    protocol_info = analyze_protocol_distribution()

    protocol_distribution = protocol_info.get(
        "protocolDistribution",
        {}
    )

    risk_weight = {

        "HTTP": 80,
        "TELNET": 95,
        "FTP": 90,
        "SMB": 75,
        "SSDP": 65,
        "mDNS": 55,
        "DHCP": 40,
        "DNS": 35,
        "ARP": 30,
        "ICMP": 25,
        "TCP": 20,
        "UDP": 20,
        "HTTPS": 10,
        "SSH": 10
    }

    protocol_risk = {}

    total_risk = 0

    for protocol, percentage in protocol_distribution.items():

        weight = risk_weight.get(
            protocol.upper(),
            50
        )

        score = round(

            (percentage * weight) / 100,

            2
        )

        protocol_risk[protocol] = score

        total_risk += score

    total_risk = round(
        total_risk,
        2
    )

    if total_risk >= 70:

        status = "High"

    elif total_risk >= 40:

        status = "Moderate"

    else:

        status = "Low"

    return {

        "protocolRiskScore":
            total_risk,

        "protocolRiskStatus":
            status,

        "protocolRisk":
            protocol_risk
    }

def analyze_protocol_health():
    """
    Protocol Health Analysis.
    """

    protocol_distribution = analyze_protocol_distribution()

    protocol_risk = analyze_protocol_risk()

    distribution = protocol_distribution.get(
        "protocolDistribution",
        {}
    )

    risk_score = protocol_risk.get(
        "protocolRiskScore",
        0
    )

    secure_percentage = round(

        distribution.get("HTTPS", 0)
        +
        distribution.get("SSH", 0),

        2
    )

    insecure_percentage = round(

        distribution.get("HTTP", 0)
        +
        distribution.get("FTP", 0)
        +
        distribution.get("TELNET", 0),

        2
    )

    health_score = round(

        (
            (100 - risk_score)
            +
            secure_percentage
            +
            (100 - insecure_percentage)
        ) / 3,

        2
    )

    if health_score >= 90:

        status = "Excellent"

    elif health_score >= 75:

        status = "Good"

    elif health_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "protocolHealthScore":
            health_score,

        "protocolHealthStatus":
            status,

        "secureProtocolPercentage":
            secure_percentage,

        "insecureProtocolPercentage":
            insecure_percentage,

        "protocolRiskScore":
            risk_score
    }

def analyze_protocol_anomalies():
    """
    Protocol Anomaly Detection.
    """

    protocol_info = analyze_protocol_distribution()

    distribution = protocol_info.get(
        "protocolDistribution",
        {}
    )

    anomalies = []

    anomaly_score = 0

    http = distribution.get("HTTP", 0)

    ftp = distribution.get("FTP", 0)

    telnet = distribution.get("TELNET", 0)

    mdns = distribution.get("mDNS", 0)

    ssdp = distribution.get("SSDP", 0)

    insecure = http + ftp + telnet

    if insecure > 20:

        anomalies.append(
            "High insecure protocol usage"
        )

        anomaly_score += 30

    if (mdns + ssdp) > 30:

        anomalies.append(
            "Excessive service discovery traffic"
        )

        anomaly_score += 25

    known_protocols = {

        "TCP",
        "UDP",
        "ICMP",
        "ARP",
        "DNS",
        "DHCP",
        "HTTP",
        "HTTPS",
        "FTP",
        "TELNET",
        "SSH",
        "SSDP",
        "mDNS",
        "SMB"
    }

    for protocol in distribution:

        if protocol.upper() not in known_protocols:

            anomalies.append(

                f"Unknown protocol detected: {protocol}"

            )

            anomaly_score += 10

    anomaly_score = min(
        anomaly_score,
        100
    )

    if anomaly_score >= 70:

        status = "Critical"

    elif anomaly_score >= 40:

        status = "High"

    elif anomaly_score >= 20:

        status = "Moderate"

    else:

        status = "Normal"

    return {

        "protocolAnomalyScore":
            anomaly_score,

        "protocolAnomalyStatus":
            status,

        "anomalies":
            anomalies
    }

def analyze_protocol_security():
    """
    Protocol Security Score.
    """

    protocol_risk = analyze_protocol_risk()

    protocol_health = analyze_protocol_health()

    protocol_anomalies = analyze_protocol_anomalies()

    risk_score = protocol_risk.get(
        "protocolRiskScore",
        0
    )

    health_score = protocol_health.get(
        "protocolHealthScore",
        0
    )

    anomaly_score = protocol_anomalies.get(
        "protocolAnomalyScore",
        0
    )

    security_score = round(

        (
            (100 - risk_score)
            +
            health_score
            +
            (100 - anomaly_score)
        ) / 3,

        2
    )

    if security_score >= 90:

        status = "Excellent"

    elif security_score >= 75:

        status = "Good"

    elif security_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "protocolSecurityScore":
            security_score,

        "protocolSecurityStatus":
            status,

        "protocolRiskScore":
            risk_score,

        "protocolHealthScore":
            health_score,

        "protocolAnomalyScore":
            anomaly_score
    }

def analyze_traffic_pattern():
    """
    Network Traffic Pattern Analysis.
    """

    traffic_load = analyze_traffic_load()

    traffic_trend = analyze_traffic_trend()

    peak_traffic = analyze_peak_traffic()

    traffic_burst = analyze_traffic_burst()

    protocol_distribution = analyze_protocol_distribution()

    load_score = traffic_load.get(
        "trafficLoadScore",
        0
    )

    trend = traffic_trend.get(
        "trafficTrend",
        "Stable"
    )

    peak_status = peak_traffic.get(
        "peakStatus",
        "Normal"
    )

    burst = traffic_burst.get(
        "burstDetected",
        False
    )

    protocols = protocol_distribution.get(
        "protocolDistribution",
        {}
    )

    udp = protocols.get(
        "UDP",
        0
    )

    tcp = protocols.get(
        "TCP",
        0
    )

    mdns = protocols.get(
        "mDNS",
        0
    )

    ssdp = protocols.get(
        "SSDP",
        0
    )

    arp = protocols.get(
        "ARP",
        0
    )

    if (mdns + ssdp + arp) > 25:

        pattern = "Broadcast Heavy"

    elif udp > tcp and load_score > 60:

        pattern = "Streaming"

    elif tcp > 70 and load_score > 70:

        pattern = "Bulk Transfer"

    elif burst:

        pattern = "Interactive"

    elif trend == "Increasing" and peak_status == "High":

        pattern = "Mixed"

    else:

        pattern = "Normal"

    return {

        "trafficPattern":
            pattern,

        "trafficLoadScore":
            load_score,

        "trafficTrend":
            trend,

        "peakStatus":
            peak_status,

        "burstDetected":
            burst
    }

def analyze_network_utilization():
    """
    Network Utilization Profile.
    """

    bandwidth = analyze_bandwidth_utilization()

    traffic_load = analyze_traffic_load()

    congestion = analyze_traffic_congestion()

    bandwidth_utilization = bandwidth.get(
        "bandwidthUtilization",
        0
    )

    load_score = traffic_load.get(
        "trafficLoadScore",
        0
    )

    congestion_score = congestion.get(
        "congestionScore",
        0
    )

    utilization_score = round(

        (
            bandwidth_utilization
            +
            load_score
            +
            congestion_score
        ) / 3,

        2
    )

    if utilization_score >= 90:

        profile = "Saturated"

    elif utilization_score >= 70:

        profile = "Busy"

    elif utilization_score >= 40:

        profile = "Normal Usage"

    elif utilization_score >= 15:

        profile = "Light Usage"

    else:

        profile = "Idle"

    return {

        "utilizationScore":
            utilization_score,

        "utilizationProfile":
            profile,

        "bandwidthUtilization":
            bandwidth_utilization,

        "trafficLoadScore":
            load_score,

        "congestionScore":
            congestion_score
    }

def analyze_network_activity():
    """
    Network Activity Level.
    """

    global SCAN_CONTEXT

    traffic = SCAN_CONTEXT["traffic"]

    traffic_load = analyze_traffic_load()

    traffic_trend = analyze_traffic_trend()

    traffic_burst = analyze_traffic_burst()

    packet_rate = traffic.get(
        "packetRate",
        0
    )

    throughput = traffic.get(
        "throughputMbps",
        0
    )

    load_score = traffic_load.get(
        "trafficLoadScore",
        0
    )

    trend = traffic_trend.get(
        "trafficTrend",
        "Stable"
    )

    burst = traffic_burst.get(
        "burstDetected",
        False
    )

    activity_score = round(

        (
            min(packet_rate / 10, 100)
            +
            min(throughput, 100)
            +
            load_score
        ) / 3,

        2
    )

    if burst:

        activity_score = min(
            activity_score + 10,
            100
        )

    if trend == "Increasing":

        activity_score = min(
            activity_score + 5,
            100
        )

    if activity_score >= 90:

        level = "Very High"

    elif activity_score >= 70:

        level = "High"

    elif activity_score >= 40:

        level = "Moderate"

    elif activity_score >= 15:

        level = "Low"

    else:

        level = "Idle"

    return {

        "activityScore":
            round(activity_score, 2),

        "activityLevel":
            level,

        "packetRate":
            packet_rate,

        "throughputMbps":
            throughput,

        "trafficTrend":
            trend,

        "burstDetected":
            burst
    }

def analyze_network_behavior():
    """
    Network Behaviour Score.
    """

    traffic_quality = analyze_traffic_quality()

    network_utilization = analyze_network_utilization()

    network_activity = analyze_network_activity()

    traffic_congestion = analyze_traffic_congestion()

    quality_score = traffic_quality.get(
        "trafficQualityScore",
        0
    )

    utilization_score = network_utilization.get(
        "utilizationScore",
        0
    )

    activity_score = network_activity.get(
        "activityScore",
        0
    )

    congestion_score = traffic_congestion.get(
        "congestionScore",
        0
    )

    behavior_score = round(

        (
            quality_score
            +
            (100 - utilization_score)
            +
            activity_score
            +
            (100 - congestion_score)
        ) / 4,

        2
    )

    if behavior_score >= 90:

        status = "Excellent"

    elif behavior_score >= 75:

        status = "Good"

    elif behavior_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "behaviorScore":
            behavior_score,

        "behaviorStatus":
            status,

        "trafficQualityScore":
            quality_score,

        "utilizationScore":
            utilization_score,

        "activityScore":
            activity_score,

        "congestionScore":
            congestion_score
    }

def analyze_communication_pattern():
    """
    Communication Pattern Analysis.
    """

    protocol_distribution = analyze_protocol_distribution()

    traffic_pattern = analyze_traffic_pattern()

    protocols = protocol_distribution.get(
        "protocolDistribution",
        {}
    )

    pattern = traffic_pattern.get(
        "trafficPattern",
        "Normal"
    )

    tcp = protocols.get(
        "TCP",
        0
    )

    udp = protocols.get(
        "UDP",
        0
    )

    arp = protocols.get(
        "ARP",
        0
    )

    mdns = protocols.get(
        "mDNS",
        0
    )

    ssdp = protocols.get(
        "SSDP",
        0
    )

    if (mdns + ssdp) >= 30:

        communication = "Service Discovery Dominant"

    elif arp >= 20:

        communication = "Broadcast Dominant"

    elif tcp >= 60:

        communication = "Client-Server"

    elif udp >= 60:

        communication = "Peer-to-Peer"

    elif pattern == "Mixed":

        communication = "Mixed Communication"

    else:

        communication = "Client-Server"

    return {

        "communicationPattern":
            communication,

        "tcpPercentage":
            tcp,

        "udpPercentage":
            udp,

        "arpPercentage":
            arp,

        "serviceDiscoveryPercentage":
            round(
                mdns + ssdp,
                2
            )
    }

def analyze_network_efficiency():
    """
    Network Efficiency Score.
    """

    performance = analyze_network_performance()

    traffic_quality = analyze_traffic_quality()

    utilization = analyze_network_utilization()

    behavior = analyze_network_behavior()

    performance_score = performance.get(
        "performanceScore",
        0
    )

    quality_score = traffic_quality.get(
        "trafficQualityScore",
        0
    )

    utilization_score = utilization.get(
        "utilizationScore",
        0
    )

    behavior_score = behavior.get(
        "behaviorScore",
        0
    )

    efficiency_score = round(

        (
            performance_score
            +
            quality_score
            +
            (100 - utilization_score)
            +
            behavior_score
        ) / 4,

        2
    )

    global SCAN_CONTEXT

    SCAN_CONTEXT["current_efficiency_score"] = efficiency_score

    if efficiency_score >= 90:

        status = "Excellent"

    elif efficiency_score >= 75:

        status = "Good"

    elif efficiency_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "efficiencyScore":
            efficiency_score,

        "efficiencyStatus":
            status,

        "performanceScore":
            performance_score,

        "trafficQualityScore":
            quality_score,

        "utilizationScore":
            utilization_score,

        "behaviorScore":
            behavior_score
    }

def analyze_network_baseline():
    """
    Network Baseline Analysis.
    """

    global NETWORK_BASELINE_HISTORY
    global SCAN_CONTEXT

    current_score = SCAN_CONTEXT.get(
        "current_efficiency_score"
    )

    if current_score is None:

        efficiency = analyze_network_efficiency()

        current_score = efficiency.get(
            "efficiencyScore",
            0
        )

    if not SCAN_CONTEXT.get("baseline_updated", False):

        NETWORK_BASELINE_HISTORY.append(
            current_score
        )

        if len(NETWORK_BASELINE_HISTORY) > 50:

            NETWORK_BASELINE_HISTORY.pop(0)

        SCAN_CONTEXT["baseline_updated"] = True

    if len(NETWORK_BASELINE_HISTORY) < 2:

        return {

            "baselineStatus":
                "Initial Learning",

            "baselineAverage":
                current_score,

            "currentScore":
                current_score,

            "baselineDeviation":
                0
        }

    baseline_average = round(

        sum(
            NETWORK_BASELINE_HISTORY
        )
        /
        len(
            NETWORK_BASELINE_HISTORY
        ),

        2
    )

    deviation = round(

        current_score
        -
        baseline_average,

        2
    )

    if deviation >= 5:

        status = "Improving"

    elif deviation <= -5:

        status = "Degrading"

    else:

        status = "Stable"

    return {

        "baselineStatus":
            status,

        "baselineAverage":
            baseline_average,

        "currentScore":
            current_score,

        "baselineDeviation":
            deviation
    }

def analyze_behavior_anomaly():
    """
    Behaviour Anomaly Detection.
    """

    baseline = analyze_network_baseline()

    behavior = analyze_network_behavior()

    burst = analyze_traffic_burst()

    congestion = analyze_traffic_congestion()

    communication = analyze_communication_pattern()

    deviation = abs(

        baseline.get(
            "baselineDeviation",
            0
        )
    )

    behavior_score = behavior.get(
        "behaviorScore",
        0
    )

    burst_detected = burst.get(
        "burstDetected",
        False
    )

    congestion_score = congestion.get(
        "congestionScore",
        0
    )

    communication_pattern = communication.get(
        "communicationPattern",
        ""
    )

    anomaly_score = 0

    if deviation >= 10:

        anomaly_score += 30

    if behavior_score < 50:

        anomaly_score += 30

    if burst_detected:

        anomaly_score += 20

    if congestion_score >= 70:

        anomaly_score += 10

    if communication_pattern == "Broadcast Dominant":

        anomaly_score += 10

    anomaly_score = min(
        anomaly_score,
        100
    )

    if anomaly_score >= 70:

        status = "Critical"

    elif anomaly_score >= 40:

        status = "High"

    elif anomaly_score >= 20:

        status = "Moderate"

    else:

        status = "Normal"

    return {

        "behaviorAnomalyScore":
            anomaly_score,

        "behaviorAnomalyStatus":
            status,

        "baselineDeviation":
            deviation,

        "behaviorScore":
            behavior_score,

        "burstDetected":
            burst_detected,

        "congestionScore":
            congestion_score,

        "communicationPattern":
            communication_pattern
    }

def analyze_behavior_intelligence():
    """
    Behaviour Intelligence Score.
    """

    behavior = analyze_network_behavior()

    efficiency = analyze_network_efficiency()

    baseline = analyze_network_baseline()

    anomaly = analyze_behavior_anomaly()

    behavior_score = behavior.get(
        "behaviorScore",
        0
    )

    efficiency_score = efficiency.get(
        "efficiencyScore",
        0
    )

    deviation = abs(

        baseline.get(
            "baselineDeviation",
            0
        )
    )

    anomaly_score = anomaly.get(
        "behaviorAnomalyScore",
        0
    )

    intelligence_score = round(

        (
            behavior_score
            +
            efficiency_score
            +
            (100 - deviation)
            +
            (100 - anomaly_score)
        ) / 4,

        2
    )

    if intelligence_score >= 90:

        status = "Excellent"

    elif intelligence_score >= 75:

        status = "Good"

    elif intelligence_score >= 50:

        status = "Fair"

    else:

        status = "Poor"

    return {

        "behaviorIntelligenceScore":
            intelligence_score,

        "behaviorIntelligenceStatus":
            status,

        "behaviorScore":
            behavior_score,

        "efficiencyScore":
            efficiency_score,

        "baselineDeviation":
            deviation,

        "behaviorAnomalyScore":
            anomaly_score
    }

def analyze_network_intelligence_summary(devices):
    """
    AI Network Intelligence Summary with transparent explainability.

    The five-factor overall score formula is preserved:
      (Health + Behavior Intelligence + Protocol Security
       + Network Efficiency + (100 - Behavior Anomaly)) / 5
    """

    performance_info = analyze_network_performance()
    reliability_info = analyze_network_reliability(devices)
    availability_info = analyze_network_availability(devices)

    health_score = round(
        (
            performance_info.get("performanceScore", 0)
            + reliability_info.get("reliabilityScore", 0)
            + availability_info.get("availabilityPercentage", 0)
        ) / 3,
        2
    )

    behavior = analyze_behavior_intelligence()
    protocol_security = analyze_protocol_security()
    efficiency = analyze_network_efficiency()
    anomaly = analyze_behavior_anomaly()

    intelligence_score = behavior.get("behaviorIntelligenceScore", 0)
    security_score = protocol_security.get("protocolSecurityScore", 0)
    efficiency_score = efficiency.get("efficiencyScore", 0)
    anomaly_score = anomaly.get("behaviorAnomalyScore", 0)

    anomaly_health_score = round(100 - anomaly_score, 2)

    factor_weight = 20

    overall_score = round(
        (
            health_score
            + intelligence_score
            + security_score
            + efficiency_score
            + anomaly_health_score
        ) / 5,
        2
    )

    if overall_score >= 90:
        overall_status = "Excellent"
    elif overall_score >= 75:
        overall_status = "Good"
    elif overall_score >= 50:
        overall_status = "Fair"
    else:
        overall_status = "Poor"

    stability_info = analyze_network_stability()
    traffic_quality_info = analyze_traffic_quality()
    utilization_info = analyze_network_utilization()
    activity_info = analyze_network_activity()
    traffic_pattern_info = analyze_traffic_pattern()
    communication_info = analyze_communication_pattern()
    baseline_info = analyze_network_baseline()

    protocol_risk_info = analyze_protocol_risk()
    protocol_health_info = analyze_protocol_health()
    protocol_anomaly_info = analyze_protocol_anomalies()

    availability_score = availability_info.get("availabilityPercentage", 0)
    performance_score = performance_info.get("performanceScore", 0)
    reliability_score = reliability_info.get("reliabilityScore", 0)
    baseline_deviation = baseline_info.get("baselineDeviation", 0)

    factor_values = [
        health_score,
        intelligence_score,
        security_score,
        efficiency_score,
        anomaly_health_score,
    ]

    factor_contributions = [
        round(
            value * factor_weight / 100,
            2
        )
        for value in factor_values
    ]

    factor_counterfactual_scores = [
        round(
            sum(
                factor_values[j]
                for j in range(len(factor_values))
                if j != i
            ) / (len(factor_values) - 1),
            2
        )
        if len(factor_values) > 1
        else 0
        for i in range(len(factor_values))
    ]

    calculated_score = round(sum(factor_contributions), 2)
    score_reconciliation = (
        "PASS"
        if calculated_score == overall_score
        else "CHECK"
    )

    factors = [
        {
            "ruleId": "NETWORK-SCORE-HEALTH-001",
            "factor": "Network Health",
            "score": health_score,
            "weight": factor_weight,
            "impact": factor_contributions[0],
            "scoreBefore": 0,
            "scoreAfter": factor_contributions[0],
            "scoreWithoutFactor": factor_counterfactual_scores[0],
            "remediationImpact": round(
                -factor_contributions[0],
                2
            ),
            "evidence": (
                f"Health score: {health_score}/100. "
                f"Availability: {availability_score}%, "
                f"performance: {performance_score}/100, "
                f"reliability: {reliability_score}/100."
            ),
            "description": (
                "Composite network health derived from availability, "
                "performance, and reliability."
            ),
            "source": "network_ai_engine",
            "sourceField": "healthScore",
            "observedValue": health_score,
            "severity": "Informational",
            "recommendation": (
                "Review availability, performance, and reliability "
                "when the health contribution is degraded."
            ),
            "role": "20% contribution to overall network score",
        },
        {
            "ruleId": "NETWORK-SCORE-BEHAVIOR-001",
            "factor": "Behavior Intelligence",
            "score": intelligence_score,
            "weight": factor_weight,
            "impact": factor_contributions[1],
            "scoreBefore": factor_contributions[0],
            "scoreAfter": round(
                sum(factor_contributions[:2]), 2
            ),
            "scoreWithoutFactor": factor_counterfactual_scores[1],
            "remediationImpact": round(
                -factor_contributions[1],
                2
            ),
            "evidence": (
                f"Behavior intelligence: {intelligence_score}/100. "
                f"Behavior score: {behavior.get('behaviorScore', 0)}/100, "
                f"efficiency score: {behavior.get('efficiencyScore', 0)}/100, "
                f"baseline deviation: {baseline_deviation}, "
                f"behavior anomaly: {anomaly_score}/100."
            ),
            "description": (
                "Behavior intelligence combines network behavior, "
                "efficiency, baseline deviation, and anomaly information."
            ),
            "source": "network_ai_engine",
            "sourceField": "behaviorIntelligenceScore",
            "observedValue": intelligence_score,
            "severity": "Informational",
            "recommendation": (
                "Review behavior, baseline deviation, bursts, and "
                "anomalies when this contribution is degraded."
            ),
            "role": "20% contribution to overall network score",
        },
        {
            "ruleId": "NETWORK-SCORE-PROTOCOL-001",
            "factor": "Protocol Security",
            "score": security_score,
            "weight": factor_weight,
            "impact": factor_contributions[2],
            "scoreBefore": round(sum(factor_contributions[:2]), 2),
            "scoreAfter": round(sum(factor_contributions[:3]), 2),
            "scoreWithoutFactor": factor_counterfactual_scores[2],
            "remediationImpact": round(
                -factor_contributions[2],
                2
            ),
            "evidence": (
                f"Protocol security: {security_score}/100. "
                f"Protocol risk: "
                f"{protocol_risk_info.get('protocolRiskScore', 0)}/100, "
                f"protocol health: "
                f"{protocol_health_info.get('protocolHealthScore', 0)}/100, "
                f"protocol anomaly: "
                f"{protocol_anomaly_info.get('protocolAnomalyScore', 0)}/100."
            ),
            "description": (
                "Protocol security combines protocol risk, protocol health, "
                "and protocol anomaly metrics."
            ),
            "source": "network_ai_engine",
            "sourceField": "protocolSecurityScore",
            "observedValue": security_score,
            "severity": "Informational",
            "recommendation": (
                "Review insecure protocols and protocol anomalies when "
                "protocol security is degraded."
            ),
            "role": "20% contribution to overall network score",
        },
        {
            "ruleId": "NETWORK-SCORE-EFFICIENCY-001",
            "factor": "Network Efficiency",
            "score": efficiency_score,
            "weight": factor_weight,
            "impact": factor_contributions[3],
            "scoreBefore": round(sum(factor_contributions[:3]), 2),
            "scoreAfter": round(sum(factor_contributions[:4]), 2),
            "scoreWithoutFactor": factor_counterfactual_scores[3],
            "remediationImpact": round(
                -factor_contributions[3],
                2
            ),
            "evidence": (
                f"Efficiency score: {efficiency_score}/100. "
                f"Performance: {efficiency.get('performanceScore', 0)}/100, "
                f"traffic quality: "
                f"{efficiency.get('trafficQualityScore', 0)}/100, "
                f"utilization: "
                f"{efficiency.get('utilizationScore', 0)}/100, "
                f"behavior: {efficiency.get('behaviorScore', 0)}/100."
            ),
            "description": (
                "Network efficiency combines performance, traffic quality, "
                "utilization, and behavior."
            ),
            "source": "network_ai_engine",
            "sourceField": "efficiencyScore",
            "observedValue": efficiency_score,
            "severity": "Informational",
            "recommendation": (
                "Review traffic quality, utilization, and performance "
                "when network efficiency is degraded."
            ),
            "role": "20% contribution to overall network score",
        },
        {
            "ruleId": "NETWORK-SCORE-ANOMALY-001",
            "factor": "Behavior Anomaly",
            "score": anomaly_health_score,
            "weight": factor_weight,
            "impact": factor_contributions[4],
            "scoreBefore": round(sum(factor_contributions[:4]), 2),
            "scoreAfter": round(sum(factor_contributions[:5]), 2),
            "scoreWithoutFactor": factor_counterfactual_scores[4],
            "remediationImpact": round(
                -factor_contributions[4],
                2
            ),
            "evidence": (
                f"Behavior anomaly: {anomaly_score}/100; "
                f"inverse contribution: {anomaly_health_score}/100. "
                f"Baseline deviation: {baseline_deviation}, "
                f"burst detected: {anomaly.get('burstDetected', False)}, "
                f"congestion: {anomaly.get('congestionScore', 0)}/100, "
                f"communication pattern: "
                f"{anomaly.get('communicationPattern', 'Unknown')}."
            ),
            "description": (
                "The anomaly factor uses the inverse of behavior anomaly "
                "so that lower anomaly produces a higher positive contribution."
            ),
            "source": "network_ai_engine",
            "sourceField": "behaviorAnomalyScore",
            "observedValue": anomaly_score,
            "severity": "Informational",
            "recommendation": (
                "Review baseline deviation, bursts, congestion, and "
                "communication patterns when anomaly is elevated."
            ),
            "role": "20% contribution using inverse anomaly score",
        },
    ]

    network_rule_catalog = {
        "NETWORK-SCORE-HEALTH-001": {
            "ruleId": "NETWORK-SCORE-HEALTH-001",
            "factor": "Network Health",
            "weight": 20,
            "description": (
                "Composite network health derived from availability, "
                "performance, and reliability."
            ),
            "source": "network_ai_engine",
            "sourceField": "healthScore",
            "role": "20% contribution to overall network score"
        },
        "NETWORK-SCORE-BEHAVIOR-001": {
            "ruleId": "NETWORK-SCORE-BEHAVIOR-001",
            "factor": "Behavior Intelligence",
            "weight": 20,
            "description": (
                "Behavior intelligence combines network behavior, "
                "efficiency, baseline deviation, and anomaly information."
            ),
            "source": "network_ai_engine",
            "sourceField": "behaviorIntelligenceScore",
            "role": "20% contribution to overall network score"
        },
        "NETWORK-SCORE-PROTOCOL-001": {
            "ruleId": "NETWORK-SCORE-PROTOCOL-001",
            "factor": "Protocol Security",
            "weight": 20,
            "description": (
                "Protocol security combines protocol risk, protocol "
                "health, and protocol anomaly metrics."
            ),
            "source": "network_ai_engine",
            "sourceField": "protocolSecurityScore",
            "role": "20% contribution to overall network score"
        },
        "NETWORK-SCORE-EFFICIENCY-001": {
            "ruleId": "NETWORK-SCORE-EFFICIENCY-001",
            "factor": "Network Efficiency",
            "weight": 20,
            "description": (
                "Network efficiency combines performance, traffic "
                "quality, utilization, and behavior."
            ),
            "source": "network_ai_engine",
            "sourceField": "efficiencyScore",
            "role": "20% contribution to overall network score"
        },
        "NETWORK-SCORE-ANOMALY-001": {
            "ruleId": "NETWORK-SCORE-ANOMALY-001",
            "factor": "Behavior Anomaly",
            "weight": 20,
            "description": (
                "The anomaly factor uses the inverse of behavior "
                "anomaly score."
            ),
            "source": "network_ai_engine",
            "sourceField": "behaviorAnomalyScore",
            "role": "20% contribution using inverse anomaly score"
        }
    }

    confidence_evidence = [
        {
            "factor": "Network Devices",
            "source": "network_scan",
            "sourceField": "devices",
            "observedValue": len(devices),
            "evidenceAvailable": bool(devices),
            "weight": 10,
        },
        {
            "factor": "Traffic Quality",
            "source": "network_ai_engine",
            "sourceField": "trafficQuality.trafficQualityScore",
            "observedValue": traffic_quality_info.get(
                "trafficQualityScore"
            ),
            "evidenceAvailable": (
                traffic_quality_info.get(
                    "trafficQualityScore"
                ) is not None
            ),
            "weight": 10,
        },
        {
            "factor": "Protocol Security",
            "source": "network_ai_engine",
            "sourceField": "protocolSecurity.protocolSecurityScore",
            "observedValue": protocol_security.get(
                "protocolSecurityScore"
            ),
            "evidenceAvailable": (
                protocol_security.get(
                    "protocolSecurityScore"
                ) is not None
            ),
            "weight": 10,
        },
        {
            "factor": "Network Efficiency",
            "source": "network_ai_engine",
            "sourceField": "networkEfficiency.efficiencyScore",
            "observedValue": efficiency.get(
                "efficiencyScore"
            ),
            "evidenceAvailable": (
                efficiency.get(
                    "efficiencyScore"
                ) is not None
            ),
            "weight": 10,
        },
        {
            "factor": "Behavior Anomaly",
            "source": "network_ai_engine",
            "sourceField": "behaviorAnomaly.behaviorAnomalyScore",
            "observedValue": anomaly.get(
                "behaviorAnomalyScore"
            ),
            "evidenceAvailable": (
                anomaly.get(
                    "behaviorAnomalyScore"
                ) is not None
            ),
            "weight": 10,
        },
    ]

    available_evidence_count = sum(
        1
        for item in confidence_evidence
        if item["evidenceAvailable"]
    )

    available_evidence_weight = sum(
        item["weight"]
        for item in confidence_evidence
        if item["evidenceAvailable"]
    )

    total_evidence_weight = sum(
        item["weight"]
        for item in confidence_evidence
    )

    confidence = min(
        100,
        50 + available_evidence_weight
    )

    explainability = {
        "version": "1.1",
        "engineVersion": "network-ai-v2",
        "ruleCatalog": network_rule_catalog,
        "summary": (
            f"The network score is {overall_score}/100 "
            f"({overall_status}). It is calculated from five "
            f"equally weighted components: network health, behavior "
            f"intelligence, protocol security, network efficiency, "
            f"and the inverse of behavior anomaly."
        ),
        "method": {
            "type": "Deterministic composite network score",
            "formula": (
                "(Health + Behavior Intelligence + Protocol Security "
                "+ Network Efficiency + (100 - Behavior Anomaly)) / 5"
            ),
            "factorWeightPercent": factor_weight,
            "factorCount": 5,
            "riskInterpretation": (
                "The score represents network security/health attention "
                "based on observed scan metrics; it is not a certainty "
                "that malicious activity exists."
            ),
        },
        "decision": {
            "riskScore": overall_score,
            "riskLevel": overall_status,
            "confidence": confidence
        },
        "calculation": {
            "healthScore": health_score,
            "behaviorIntelligenceScore": intelligence_score,
            "protocolSecurityScore": security_score,
            "networkEfficiencyScore": efficiency_score,
            "behaviorAnomalyScore": anomaly_score,
            "anomalyHealthScore": anomaly_health_score,
            "factorWeightPercent": factor_weight,
            "factorContributions": factor_contributions,
            "factorCount": len(factors),
            "calculatedScore": calculated_score,
            "finalScore": overall_score,
            "evidenceComplete": (
                available_evidence_count == len(confidence_evidence)
            ),
            "reconciliation": score_reconciliation,
            "formulaTrace": (
                f"({health_score} + {intelligence_score} + "
                f"{security_score} + {efficiency_score} + "
                f"{anomaly_health_score}) / 5 = {calculated_score}"
            ),
        },
        "confidence": {
            "score": confidence,
            "baseScore": 50,
            "availableEvidenceCount": available_evidence_count,
            "totalEvidenceCount": len(confidence_evidence),
            "availableEvidenceWeight": available_evidence_weight,
            "totalEvidenceWeight": total_evidence_weight,
            "formula": "50 + sum(weight for available evidence)",
            "evidenceComplete": (
                available_evidence_count == len(confidence_evidence)
            ),
            "summary": (
                f"Network confidence is {confidence}% based on "
                f"{available_evidence_count} available evidence sources out of "
                f"{len(confidence_evidence)} evaluated evidence sources."
            ),
            "calculation": {
                "baseScore": 50,
                "availableEvidenceWeight": available_evidence_weight,
                "totalEvidenceWeight": total_evidence_weight,
                "availableEvidenceCount": available_evidence_count,
                "totalEvidenceCount": len(confidence_evidence),
                "formula": "50 + sum(weight for available evidence)",
                "maxScore": 100,
                "finalScore": confidence
            },
            "factors": confidence_evidence,
        },
        "factors": factors,
        "observations": [
            {
                "name": "Network Availability",
                "value": availability_score,
                "source": "network_ai_engine",
                "sourceField": "networkAvailability.availabilityPercentage",
                "detail": (
                    f"{availability_info.get('onlineDevices', 0)} of "
                    f"{availability_info.get('totalDevices', 0)} devices "
                    f"are online."
                ),
            },
            {
                "name": "Network Stability",
                "value": stability_info.get("stabilityScore", 0),
                "source": "network_ai_engine",
                "sourceField": "networkStability.stabilityScore",
                "detail": (
                    f"Stability status: "
                    f"{stability_info.get('stabilityStatus', 'Unknown')}."
                ),
            },
            {
                "name": "Traffic Quality",
                "value": traffic_quality_info.get("trafficQualityScore", 0),
                "source": "network_ai_engine",
                "sourceField": "trafficQuality.trafficQualityScore",
                "detail": (
                    f"Traffic quality status: "
                    f"{traffic_quality_info.get('trafficQualityStatus', 'Unknown')}."
                ),
            },
            {
                "name": "Network Utilization",
                "value": utilization_info.get("utilizationScore", 0),
                "source": "network_ai_engine",
                "sourceField": "networkUtilization.utilizationScore",
                "detail": (
                    f"Utilization profile: "
                    f"{utilization_info.get('utilizationProfile', 'Unknown')}."
                ),
            },
            {
                "name": "Network Activity",
                "value": activity_info.get("activityScore", 0),
                "source": "network_ai_engine",
                "sourceField": "networkActivity.activityScore",
                "detail": (
                    f"Activity level: "
                    f"{activity_info.get('activityLevel', 'Unknown')}."
                ),
            },
        ],
        "patterns": [
            {
                "name": "Traffic Pattern",
                "value": traffic_pattern_info.get("trafficPattern", "Normal"),
                "detail": (
                    f"Traffic trend: "
                    f"{traffic_pattern_info.get('trafficTrend', 'Stable')}; "
                    f"peak status: "
                    f"{traffic_pattern_info.get('peakStatus', 'Normal')}; "
                    f"burst detected: "
                    f"{traffic_pattern_info.get('burstDetected', False)}."
                ),
            },
            {
                "name": "Communication Pattern",
                "value": communication_info.get(
                    "communicationPattern",
                    "Unknown"
                ),
                "detail": (
                    f"TCP: {communication_info.get('tcpPercentage', 0)}%, "
                    f"UDP: {communication_info.get('udpPercentage', 0)}%, "
                    f"ARP: {communication_info.get('arpPercentage', 0)}%, "
                    f"service discovery: "
                    f"{communication_info.get('serviceDiscoveryPercentage', 0)}%."
                ),
            },
            {
                "name": "Baseline",
                "value": baseline_info.get("baselineStatus", "Unknown"),
                "detail": (
                    f"Baseline average: "
                    f"{baseline_info.get('baselineAverage', 0)}, "
                    f"current score: "
                    f"{baseline_info.get('currentScore', 0)}, "
                    f"deviation: {baseline_deviation}."
                ),
            },
        ],
        "recommendations": [],
        "limitations": [
            "The explanation uses metrics available during the current scan.",
            "The overall score is a deterministic composite metric.",
            "Behavior anomaly contribution is the inverse of the anomaly score.",
            "Baseline interpretation becomes more meaningful after multiple scans.",
            "The score alone does not establish that malicious activity exists.",
        ],
    }

    if protocol_anomaly_info.get("protocolAnomalyScore", 0) >= 20:
        explainability["recommendations"].append({
            "ruleId": "NETWORK-SCORE-PROTOCOL-001",
            "factor": "Protocol Security",
            "severity": "Medium",
            "observedValue": protocol_anomaly_info.get(
                "protocolAnomalyScore", 0
            ),
            "action": "Review protocol anomalies and unusual protocol usage.",
        })

    if anomaly_score >= 20:
        explainability["recommendations"].append({
            "ruleId": "NETWORK-SCORE-ANOMALY-001",
            "factor": "Behavior Anomaly",
            "severity": "Medium",
            "observedValue": anomaly_score,
            "action": (
                "Review behavior anomaly indicators, baseline deviation, "
                "traffic bursts, and congestion."
            ),
        })

    if availability_score < 95:
        explainability["recommendations"].append({
            "ruleId": "NETWORK-SCORE-HEALTH-001",
            "factor": "Network Health",
            "severity": "Medium",
            "observedValue": availability_score,
            "action": "Review offline devices and network availability.",
        })

    if utilization_info.get("utilizationScore", 0) >= 70:
        explainability["recommendations"].append({
            "ruleId": "NETWORK-SCORE-EFFICIENCY-001",
            "factor": "Network Efficiency",
            "severity": "Medium",
            "observedValue": utilization_info.get("utilizationScore", 0),
            "action": "Review network utilization and congestion.",
        })

    if not explainability["recommendations"]:
        explainability["recommendations"].append({
            "ruleId": None,
            "factor": "Network Assessment",
            "severity": "Informational",
            "observedValue": overall_score,
            "action": (
                "No additional action is indicated by the current "
                "network-level metrics."
            ),
        })

    return {
        "overallNetworkScore": overall_score,
        "overallNetworkStatus": overall_status,
        "healthScore": health_score,
        "behaviorIntelligenceScore": intelligence_score,
        "protocolSecurityScore": security_score,
        "networkEfficiencyScore": efficiency_score,
        "behaviorAnomalyScore": anomaly_score,
        "explainability": explainability,
    }
