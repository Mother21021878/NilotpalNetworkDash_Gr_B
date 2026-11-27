import hashlib
import time

FLOW_CACHE = {}
DHCP_CACHE = {}
DHCP_SECURITY_CACHE = {
    "servers": set(),
    "assignedIps": {}
}
NTP_SECURITY_CACHE = {
    "servers": set(),
    "lastReferenceId": None
}
SNMP_SECURITY_CACHE = {
    "trapCount": 0
}

def analyze_packet(packet):
    """
    AI Packet Analysis Engine
    """

    flow = update_flow_cache(packet)

    return {
        "aiSummary": generate_ai_summary(packet),
        "packetClassification": classify_packet(packet),
        "trafficType": detect_traffic_type(packet),
        "application": detect_application(packet),
        "protocolAnalysis": analyze_protocol(packet),
        "tcpAnalysis": analyze_tcp(packet),
        "udpAnalysis": analyze_udp(packet),
        "icmpAnalysis": analyze_icmp(packet), 
        "arpAnalysis": analyze_arp(packet),
        "dnsAnalysis": analyze_dns(packet),
        "dhcpConversation": analyze_dhcp_conversation(packet),
        "dhcpHealth": analyze_dhcp_health(packet),
        "dhcpSecurity": analyze_dhcp_security(packet),
        "dhcpAnalysis": analyze_dhcp(packet),
        "ntpAnalysis": analyze_ntp(packet),
        "ntpHealth": analyze_ntp_health(packet),
        "ntpSecurity": analyze_ntp_security(packet),
        "snmpAnalysis": analyze_snmp(packet),
        "snmpHealth": analyze_snmp_health(packet),
        "snmpSecurity": analyze_snmp_security(packet),
        "sessionType": detect_session_type(packet),
        "communicationDirection": detect_communication_direction(packet),
        "flowId": generate_flow_id(packet),
        "flowStatistics": flow,
        "flowMetrics": calculate_flow_statistics(flow),
        "interPacketGap": calculate_inter_packet_gap(flow),
        "gapStatistics": calculate_gap_statistics(flow),
        "jitterStatistics": calculate_jitter_statistics(flow),
        "idleStatistics": calculate_idle_statistics(flow),
        "flowLifetime": calculate_flow_lifetime(flow),
        "burstStatistics": calculate_burst_statistics(flow),
        "directionStatistics": calculate_direction_statistics(flow),
        "payloadStatistics": calculate_payload_statistics(flow),
        "retransmissionStatistics": calculate_retransmission_statistics(flow),
        "outOfOrderStatistics": calculate_out_of_order_statistics(flow),
        "windowStatistics": calculate_window_statistics(flow),
        "flowEfficiency": calculate_flow_efficiency(flow),
        "tcpFlagStatistics": calculate_tcp_flag_statistics(flow),
        "flowResetStatistics": calculate_flow_reset_statistics(flow),
        "connectionQuality": calculate_connection_quality(flow),
        "flowReliability": calculate_flow_reliability(flow),
        "flowStability": calculate_flow_stability(flow),
        "conversationPattern": detect_conversation_pattern(packet, flow),
        "flowBehavior": analyze_flow_behavior(flow),
        "flowAnomaly": detect_flow_anomaly(flow),
        "flowPerformance": analyze_flow_performance(flow),
        "flowClassification": classify_flow(packet, flow),
        "flowPriority": assess_flow_priority(packet, flow),
        "flowSLA": assess_flow_sla(flow),
        "flowCongestion": analyze_flow_congestion(flow),
        "flowLatency": assess_flow_latency(flow),
        "pathQuality": assess_network_path_quality(flow),
        "flowQoS": assess_flow_qos(flow),
        "flowExperience": assess_flow_experience(flow),
        "flowServiceProfile": assess_flow_service_profile(packet, flow),
        "flowCapacity": assess_flow_capacity(flow),
        "flowUtilization": assess_flow_utilization(flow),
        "flowResources": assess_flow_resources(flow),
        "flowAvailability": assess_flow_availability(packet, flow),
        "flowResilience": assess_flow_resilience(flow),
        "flowContinuity": assess_flow_continuity(flow),
        "flowDurability": assess_flow_durability(flow),
        "flowRobustness": assess_flow_robustness(flow),
        "flowConsistency": assess_flow_consistency(flow),
        "flowRecoverability": assess_flow_recoverability(flow),
        "flowMaintainability": assess_flow_maintainability(flow),
        "flowSustainability": assess_flow_sustainability(flow),
        "flowTrend": analyze_flow_trend(flow),
        "flowAnalyticsSummary": generate_flow_analytics_summary(packet, flow),
        "flowState": detect_flow_state(flow),
        "flowTermination": detect_flow_termination(packet, flow),
        "flowRisk": assess_flow_risk(packet, flow),
        "flowHealthScore": calculate_flow_health_score(packet, flow),
        "flowSummary": generate_flow_summary(packet, flow),
        "packetQuality": analyze_packet_quality(packet),
        "aiVerdict": generate_ai_verdict(packet),
        "riskScore": 0,
        "confidence": 0
    }

def classify_packet(packet):
    """
    Classify packet based on protocol and port numbers.
    """

    protocol = (packet.get("protocol") or "").upper()

    src_port = int(packet.get("sourcePort") or 0)
    dst_port = int(packet.get("destinationPort") or 0)

    ports = {src_port, dst_port}


    # Discovery Protocols
    if protocol in ("ARP", "LLMNR", "MDNS", "SSDP", "NBNS"):
        return "Discovery Traffic"


    # Network Infrastructure
    if protocol in ("DHCP", "ICMP", "IGMP"):
        return "Network Management"


    # DNS
    if protocol == "DNS":
        return "Name Resolution"


    # Web
    if ports & {80, 443, 8080, 8443}:
        return "Application Traffic"


    # Remote Management
    if ports & {22, 23, 3389}:
        return "Remote Management"


    # File Transfer
    if ports & {20, 21, 69}:
        return "File Transfer"


    # Mail
    if ports & {25, 110, 143, 465, 587, 993, 995}:
        return "Mail Traffic"


    # Streaming
    if ports & {554, 8554}:
        return "Streaming Traffic"


    # Default
    return "General Traffic"

def detect_traffic_type(packet):
    """
    Determine whether the packet is Unicast, Broadcast or Multicast.
    """

    destination = (
        packet.get("destination")
        or packet.get("destinationIp")
        or ""
    ).strip()

    destination = destination.upper()

    
    # IPv4 Broadcast
    if destination == "255.255.255.255":
        return "Broadcast"

    # Ethernet Broadcast
    if destination == "FF:FF:FF:FF:FF:FF":
        return "Broadcast"

    # IPv4 Multicast
    if destination.startswith("224.") \
       or destination.startswith("225.") \
       or destination.startswith("226.") \
       or destination.startswith("227.") \
       or destination.startswith("228.") \
       or destination.startswith("229.") \
       or destination.startswith("230.") \
       or destination.startswith("231.") \
       or destination.startswith("232.") \
       or destination.startswith("233.") \
       or destination.startswith("234.") \
       or destination.startswith("235.") \
       or destination.startswith("236.") \
       or destination.startswith("237.") \
       or destination.startswith("238.") \
       or destination.startswith("239."):
        return "Multicast"

    # Ethernet Multicast
    if destination.startswith("01:00:5E"):
        return "Multicast"

    return "Unicast"

def detect_application(packet):
    """
    Detect application/service based on protocol and port numbers.
    """

    protocol = (packet.get("protocol") or "").upper()

    src_port = int(packet.get("sourcePort") or 0)
    dst_port = int(packet.get("destinationPort") or 0)

    ports = {src_port, dst_port}

    # Protocol-first detection
    if protocol == "HTTP":
        return "HTTP"

    if protocol == "HTTPS":
        return "HTTPS"

    if protocol == "DNS":
        return "DNS"

    if protocol == "DHCP":
        return "DHCP"

    if protocol == "MDNS":
        return "mDNS"

    if protocol == "SSDP":
        return "SSDP"

    if protocol == "NBNS":
        return "NetBIOS"

    if protocol == "NTP":
        return "NTP"

    # Port-based detection
    application_ports = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        123: "NTP",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        161: "SNMP",
        162: "SNMP Trap",
        1900: "SSDP",
        5353: "mDNS",
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        445: "SMB",
        554: "RTSP",
        3389: "RDP",
        1883: "MQTT",
        8883: "MQTT Secure"
    }

    for port in ports:
        if port in application_ports:
            return application_ports[port]

    return "Unknown"

def detect_session_type(packet):
    """
    Identify the packet's role within a communication session.
    """

    protocol = (packet.get("protocol") or "").upper()

    src_port = int(packet.get("sourcePort") or 0)
    dst_port = int(packet.get("destinationPort") or 0)

    flags = (packet.get("flags") or "").upper()

    # TCP Handshake
    if "SYN" in flags and "ACK" not in flags:
        return "Handshake"

    if "SYN" in flags and "ACK" in flags:
        return "Handshake"

    # TCP Keep Alive
    if "KEEP" in flags:
        return "Keep Alive"

    # Discovery Protocols
    if protocol in ("ARP", "MDNS", "SSDP", "NBNS", "LLMNR"):
        return "Discovery"

    # DHCP
    if protocol == "DHCP":
        return "Discovery"

    # Request
    client_ports = {
        80, 443, 53, 67, 68, 69,
        123, 161, 1900, 5353,
        20, 21, 22, 23,
        25, 110, 143,
        445, 554, 3389,
        1883, 8883
    }

    if dst_port in client_ports:
        return "Request"

    if src_port in client_ports:
        return "Response"

    return "Unknown"

def detect_communication_direction(packet):
    """
    Determine communication direction.
    """

    traffic_type = detect_traffic_type(packet)

    if traffic_type == "Broadcast":
        return "Broadcast"

    if traffic_type == "Multicast":
        return "Multicast"

    src_port = int(packet.get("sourcePort") or 0)
    dst_port = int(packet.get("destinationPort") or 0)

    server_ports = {
        20, 21, 22, 23,
        25, 53, 67, 68,
        69, 80, 110, 123,
        137, 138, 139, 143,
        161, 162, 443, 445,
        554, 1900, 3389,
        5353, 1883, 8883
    }

    # Client -> Server
    if dst_port in server_ports and src_port not in server_ports:
        return "Client → Server"

    # Server -> Client
    if src_port in server_ports and dst_port not in server_ports:
        return "Server → Client"

    # Same class of devices
    return "Peer ↔ Peer"

def generate_ai_verdict(packet):
    """
    Generate AI verdict for the packet.
    """

    classification = classify_packet(packet)
    application = detect_application(packet)
    session = detect_session_type(packet)
    direction = detect_communication_direction(packet)

    # Discovery
    if classification == "Discovery Traffic":
        return "Network Discovery Activity"

    # DNS
    if application == "DNS":
        return "DNS Name Resolution"

    # DHCP
    if application == "DHCP":
        return "IP Address Assignment"

    # Web
    if application in ("HTTP", "HTTPS"):
        return "Normal Web Traffic"

    # Remote Access
    if application in ("SSH", "Telnet", "RDP"):
        return "Remote Administration Session"

    # File Sharing
    if application in ("FTP", "SMB"):
        return "File Transfer Activity"

    # Multimedia
    if application == "RTSP":
        return "Streaming Media Session"

    # IoT
    if application.startswith("MQTT"):
        return "IoT Device Communication"

    # General Request
    if session == "Request" and direction == "Client → Server":
        return "Normal Client Request"

    # General Response
    if session == "Response" and direction == "Server → Client":
        return "Normal Server Response"

    return "General Network Traffic"

def generate_ai_summary(packet):
    """
    Generate a human-readable AI summary for the packet.
    """

    application = detect_application(packet)
    session = detect_session_type(packet)
    direction = detect_communication_direction(packet)
    traffic = detect_traffic_type(packet)

    # Discovery
    if session == "Discovery":
        return f"{application} discovery packet using {traffic.lower()} communication."

    # Request
    if session == "Request":
        return (
            f"{application} request from client to server "
            f"over {traffic.lower()} communication."
        )

    # Response
    if session == "Response":
        return (
            f"{application} response from server to client "
            f"over {traffic.lower()} communication."
        )

    # Handshake
    if session == "Handshake":
        return (
            f"TCP handshake establishing a "
            f"{direction.lower()} connection."
        )

    # Keep Alive
    if session == "Keep Alive":
        return (
            f"TCP keep-alive packet maintaining the connection."
        )

    return (
        f"{application} packet exchanged via "
        f"{traffic.lower()} communication."
    )

def generate_flow_id(packet):
    """
    Generate a unique Flow ID for a packet.
    """

    src_ip = packet.get("sourceIp", "")
    dst_ip = packet.get("destinationIp", "")
    src_port = packet.get("sourcePort", 0)
    dst_port = packet.get("destinationPort", 0)
    protocol = packet.get("protocol", "").upper()

    # Make flow bidirectional
    endpoints = sorted([
        f"{src_ip}:{src_port}",
        f"{dst_ip}:{dst_port}"
    ])

    flow_string = (
        f"{protocol}|"
        f"{endpoints[0]}|"
        f"{endpoints[1]}"
    )

    return hashlib.md5(flow_string.encode()).hexdigest()[:16]

def update_flow_cache(packet):
    """
    Update runtime statistics for each flow.
    """

    flow_id = generate_flow_id(packet)

    now = time.time()

    packet_size = int(packet.get("length") or packet.get("packetLength") or 0)

    if flow_id not in FLOW_CACHE:

        FLOW_CACHE[flow_id] = {
            "flowId": flow_id,
            "firstSeen": now,
            "lastSeen": now,
            "previousSeen": now,
            "packetCount": 0,
            "totalBytes": 0,
            "sourceIp": packet.get("sourceIp", ""),
            "destinationIp": packet.get("destinationIp", ""),
            "protocol": packet.get("protocol", ""),
            "gapTotal": 0.0,
            "gapCount": 0,
            "minGap": None,
            "maxGap": 0.0,
            "previousGap": None,
            "jitterTotal": 0.0,
            "jitterCount": 0,
            "maximumJitter": 0.0,
            "maximumIdleTime": 0.0,
            "idleEventCount": 0,
            "flowTimeout": 120,
            "burstPacketCount": 0,
            "burstStartTime": now,
            "burstEndTime": now,
            "clientToServerPackets": 0,
            "serverToClientPackets": 0,
            "payloadBytes": 0,
            "headerBytes": 0,
            "retransmissionCount": 0,
            "lastSequenceNumber": None,
            "outOfOrderCount": 0,
            "windowSizeTotal": 0,
            "windowSamples": 0,
            "minimumWindowSize": None,
            "maximumWindowSize": 0,
            "currentWindowSize": 0,
            "synCount": 0,
            "ackCount": 0,
            "finCount": 0,
            "rstCount": 0,
            "pshCount": 0,
            "urgCount": 0,
            "gracefulTerminationCount": 0,
            "resetTerminationCount": 0
        }

    flow = FLOW_CACHE[flow_id]
    previous_seen = flow["lastSeen"]

    flow["previousSeen"] = previous_seen
    flow["lastSeen"] = now
    flow["packetCount"] += 1
    flow["burstPacketCount"] += 1
    flow["burstEndTime"] = now
    flow["totalBytes"] += packet_size
    direction = detect_communication_direction(packet)
    payload_size = int(packet.get("payloadLength") or 0)
    flow["payloadBytes"] += payload_size
    flow["headerBytes"] += max(
        packet_size - payload_size,
        0
    )
    sequence = packet.get("sequenceNumber")

    if sequence is not None:
        previous = flow["lastSequenceNumber"]

        if previous == sequence:
            flow["retransmissionCount"] += 1
        elif previous is not None and sequence < previous:
            flow["outOfOrderCount"] += 1

        flow["lastSequenceNumber"] = sequence

        window_size = packet.get("windowSize")

        if window_size is not None:

            window_size = int(window_size)
            flow["currentWindowSize"] = window_size
            flow["windowSizeTotal"] += window_size
            flow["windowSamples"] += 1

            if (
                flow["minimumWindowSize"] is None
                or
                window_size < flow["minimumWindowSize"]
            ):

                flow["minimumWindowSize"] = window_size

            if window_size > flow["maximumWindowSize"]:

                flow["maximumWindowSize"] = window_size

            flags = (packet.get("flags") or "").upper()

            if "SYN" in flags:
                flow["synCount"] += 1

            if "ACK" in flags:
                flow["ackCount"] += 1

            if "FIN" in flags:
                flow["finCount"] += 1
                flow["gracefulTerminationCount"] += 1

            if "RST" in flags:
                flow["rstCount"] += 1
                flow["resetTerminationCount"] += 1

            if "PSH" in flags:
                flow["pshCount"] += 1

            if "URG" in flags:
                flow["urgCount"] += 1

    if direction == "Client → Server":
        flow["clientToServerPackets"] += 1

    elif direction == "Server → Client":
        flow["serverToClientPackets"] += 1

    gap = flow["lastSeen"] - flow["previousSeen"]

    if gap > 0:

        flow["gapTotal"] += gap
        flow["gapCount"] += 1

        if flow["minGap"] is None or gap < flow["minGap"]:
            flow["minGap"] = gap

        if gap > flow["maxGap"]:
            flow["maxGap"] = gap

    if gap > 0:

        previous_gap = flow["previousGap"]

        if previous_gap is not None:

            jitter = abs(gap - previous_gap)
            flow["jitterTotal"] += jitter
            flow["jitterCount"] += 1

            if jitter > flow["maximumJitter"]:
                flow["maximumJitter"] = jitter

        flow["previousGap"] = gap

    return flow

def calculate_flow_statistics(flow):
    """
    Calculate flow duration and throughput statistics.
    """

    duration = flow["lastSeen"] - flow["firstSeen"]

    if duration <= 0:
        duration = 0.001

    packet_count = flow["packetCount"]
    total_bytes = flow["totalBytes"]

    return {
        "flowDuration": round(duration, 3),
        "averagePacketSize": round(total_bytes / packet_count, 2),
        "packetsPerSecond": round(packet_count / duration, 2),
        "bytesPerSecond": round(total_bytes / duration, 2)
    }

def calculate_inter_packet_gap(flow):
    """
    Calculate the time between consecutive packets in a flow.
    """

    gap = flow["lastSeen"] - flow["previousSeen"]

    idle_time = max(gap, 0)

    if idle_time > flow["maximumIdleTime"]:
        flow["maximumIdleTime"] = idle_time

    if idle_time >= 1.0:
        flow["idleEventCount"] += 1

    return round(max(gap, 0), 6)

def calculate_gap_statistics(flow):
    """
    Calculate inter-packet timing statistics.
    """

    if flow["gapCount"] == 0:

        average_gap = 0.0

    else:

        average_gap = flow["gapTotal"] / flow["gapCount"]

    return {

        "averageGap": round(average_gap, 6),

        "minimumGap": round(flow["minGap"] or 0, 6),

        "maximumGap": round(flow["maxGap"], 6),

        "samples": flow["gapCount"]
    }

def calculate_jitter_statistics(flow):
    """
    Calculate packet jitter statistics.
    """

    if flow["jitterCount"] == 0:

        average_jitter = 0.0

    else:

        average_jitter = (
            flow["jitterTotal"] /
            flow["jitterCount"]
        )

    return {

        "averageJitter": round(average_jitter, 6),

        "maximumJitter": round(
            flow["maximumJitter"], 6
        ),

        "samples": flow["jitterCount"]
    }

def calculate_idle_statistics(flow):
    """
    Calculate flow idle time statistics.
    """

    current_idle = round(
        max(time.time() - flow["lastSeen"], 0),
        6
    )

    return {

        "currentIdleTime": current_idle,

        "maximumIdleTime": round(
            flow["maximumIdleTime"], 6
        ),

        "idleEvents": flow["idleEventCount"]
    }

def calculate_flow_lifetime(flow):
    """
    Calculate flow lifetime information.
    """

    now = time.time()
    age = now - flow["firstSeen"]
    idle = now - flow["lastSeen"]

    remaining = max(
        flow["flowTimeout"] - idle,
        0
    )

    return {

        "flowAge": round(age, 3),
        "idleTime": round(idle, 3),
        "remainingTime": round(remaining, 3),
        "timeout": flow["flowTimeout"]
    }

def calculate_burst_statistics(flow):
    """
    Calculate burst traffic statistics.
    """

    duration = (
        flow["burstEndTime"] -
        flow["burstStartTime"]
    )

    if duration <= 0:

        duration = 0.001

    return {

        "burstPackets": flow["burstPacketCount"],
        "burstDuration": round(duration, 3),

        "burstRate": round(
            flow["burstPacketCount"] / duration,
            2
        )
    }

def calculate_direction_statistics(flow):
    """
    Calculate packet direction statistics.
    """

    client_packets = flow["clientToServerPackets"]
    server_packets = flow["serverToClientPackets"]
    total = client_packets + server_packets

    if total == 0:

        ratio = "0:0"

    else:

        ratio = (
            f"{client_packets}:{server_packets}"
        )

    return {

        "clientToServerPackets": client_packets,
        "serverToClientPackets": server_packets,
        "directionRatio": ratio
    }

def calculate_payload_statistics(flow):
    """
    Calculate payload transfer statistics.
    """

    total_bytes = flow["totalBytes"]
    payload_bytes = flow["payloadBytes"]

    packet_count = max(
        flow["packetCount"],
        1
    )

    efficiency = 0.0

    if total_bytes > 0:

        efficiency = (
            payload_bytes * 100 /
            total_bytes
        )

    return {

        "payloadBytes": payload_bytes,
        "headerBytes": flow["headerBytes"],

        "averagePayloadSize": round(
            payload_bytes / packet_count,
            2
        ),

        "payloadEfficiency": round(
            efficiency,
            2
        )
    }

def calculate_retransmission_statistics(flow):
    """
    Calculate TCP retransmission statistics.
    """

    packet_count = max(
        flow["packetCount"],
        1
    )

    percentage = (
        flow["retransmissionCount"] * 100 /
        packet_count
    )

    return {

        "retransmissionCount":
            flow["retransmissionCount"],

        "retransmissionPercentage":
            round(percentage, 2)
    }

def calculate_out_of_order_statistics(flow):
    """
    Calculate out-of-order packet statistics.
    """

    packet_count = max(
        flow["packetCount"],
        1
    )

    ordered_percentage = (
        (packet_count - flow["outOfOrderCount"])
        * 100
        / packet_count
    )

    return {

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "orderedPacketPercentage":
            round(
                ordered_percentage,
                2
            )
    }

def calculate_window_statistics(flow):
    """
    Calculate TCP receive window statistics.
    """

    samples = max(
        flow["windowSamples"],
        1
    )

    return {

        "currentWindowSize":
            flow["currentWindowSize"],

        "averageWindowSize":
            round(
                flow["windowSizeTotal"] / samples,
                2
            ),

        "minimumWindowSize":
            flow["minimumWindowSize"] or 0,

        "maximumWindowSize":
            flow["maximumWindowSize"]
    }

def calculate_flow_efficiency(flow):
    """
    Calculate flow efficiency statistics.
    """

    total_bytes = max(
        flow["totalBytes"],
        1
    )

    packet_count = max(
        flow["packetCount"],
        1
    )

    payload_efficiency = (
        flow["payloadBytes"] * 100
        / total_bytes
    )

    header_overhead = (
        flow["headerBytes"] * 100
        / total_bytes
    )

    return {

        "payloadEfficiency":
            round(payload_efficiency, 2),

        "headerOverhead":
            round(header_overhead, 2),

        "averageBytesPerPacket":
            round(
                total_bytes / packet_count,
                2
            )
    }

def calculate_tcp_flag_statistics(flow):
    """
    Calculate TCP flag statistics for the flow.
    """

    return {

        "synPackets":
            flow["synCount"],

        "ackPackets":
            flow["ackCount"],

        "finPackets":
            flow["finCount"],

        "rstPackets":
            flow["rstCount"],

        "pshPackets":
            flow["pshCount"],

        "urgPackets":
            flow["urgCount"]
    }

def calculate_flow_reset_statistics(flow):
    """
    Calculate TCP flow reset statistics.
    """

    terminations = max(
        flow["gracefulTerminationCount"] +
        flow["resetTerminationCount"],
        1
    )

    return {

        "gracefulTerminations":
            flow["gracefulTerminationCount"],

        "resetTerminations":
            flow["resetTerminationCount"],

        "resetRatio":
            round(
                (
                    flow["resetTerminationCount"] * 100
                ) / terminations,
                2
            )
    }

def calculate_connection_quality(flow):
    """
    Calculate overall TCP connection quality.
    """

    packet_count = max(
        flow["packetCount"],
        1
    )

    retransmission_percent = (
        flow["retransmissionCount"] * 100
        / packet_count
    )

    out_of_order_percent = (
        flow["outOfOrderCount"] * 100
        / packet_count
    )

    score = (
        100
        - retransmission_percent
        - out_of_order_percent
    )

    score = max(
        0,
        round(score, 2)
    )

    if score >= 95:
        quality = "Excellent"

    elif score >= 85:
        quality = "Good"

    elif score >= 70:
        quality = "Fair"

    else:
        quality = "Poor"

    return {

        "quality": quality,

        "qualityScore": score,

        "retransmissionImpact":
            round(retransmission_percent, 2),

        "outOfOrderImpact":
            round(out_of_order_percent, 2)
    }

def calculate_flow_reliability(flow):
    """
    Calculate flow reliability statistics.
    """

    packet_count = max(
        flow["packetCount"],
        1
    )

    successful_packets = (
        packet_count
        - flow["retransmissionCount"]
        - flow["outOfOrderCount"]
    )

    successful_packets = max(
        successful_packets,
        0
    )

    reliability = (
        successful_packets * 100
        / packet_count
    )

    integrity = (
        100
        - (
            flow["retransmissionCount"]
            + flow["outOfOrderCount"]
        ) * 100 / packet_count
    )

    reliability = round(
        max(reliability, 0),
        2
    )

    integrity = round(
        max(integrity, 0),
        2
    )

    return {

        "packetDeliveryRate":
            reliability,

        "packetIntegrity":
            integrity,

        "reliableFlow":
            reliability >= 95,

        "reliabilityPercentage":
            reliability
    }

def calculate_flow_stability(flow):
    """
    Calculate overall flow stability.
    """

    score = 100.0

    packet_count = max(
        flow["packetCount"],
        1
    )

    retransmission_percent = (
        flow["retransmissionCount"] * 100
        / packet_count
    )

    out_of_order_percent = (
        flow["outOfOrderCount"] * 100
        / packet_count
    )

    average_jitter = 0.0

    if flow["jitterCount"] > 0:

        average_jitter = (
            flow["jitterTotal"]
            / flow["jitterCount"]
        )

    score -= retransmission_percent
    score -= out_of_order_percent
    score -= average_jitter * 10
    score -= flow["idleEventCount"] * 2

    score = round(
        max(score, 0),
        2
    )

    if score >= 95:
        status = "Excellent"

    elif score >= 85:
        status = "Good"

    elif score >= 70:
        status = "Fair"

    else:
        status = "Poor"

    return {

        "stabilityScore":
            score,

        "stabilityStatus":
            status,

        "stableFlow":
            score >= 85,

        "stabilityPercentage":
            score
    }

def detect_conversation_pattern(packet, flow):
    """
    Detect communication pattern for the flow.
    """

    traffic = detect_traffic_type(packet)

    if traffic == "Broadcast":
        return "Broadcast"

    if traffic == "Multicast":
        return "Multicast"

    direction = detect_communication_direction(packet)

    if direction == "Peer ↔ Peer":
        return "Peer-to-Peer"

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    if (
        flow["clientToServerPackets"] > 0
        and
        flow["serverToClientPackets"] > 0
    ):

        if duration >= 60:
            return "Long-Lived Client-Server"

        return "Request-Response"

    if duration >= 60:
        return "Long-Lived Session"

    return "Short-Lived Session"

def analyze_flow_behavior(flow):
    """
    Analyze overall communication behavior of the flow.
    """

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    packets = flow["packetCount"]

    pps = (
        packets /
        max(duration, 0.001)
    )

    average_gap = (
        flow["gapTotal"] /
        max(flow["gapCount"], 1)
    )

    if pps >= 500:
        return "Bulk Transfer"

    if average_gap < 0.02:
        return "Chatty"

    if flow["burstPacketCount"] >= 100:
        return "Bursty"

    if average_gap >= 5:
        return "Silent"

    if (
        flow["jitterCount"] >= 5
        and
        flow["maximumJitter"] < 0.005
    ):
        return "Periodic"

    return "Interactive"

def detect_flow_anomaly(flow):
    """
    Detect abnormal behaviour within a network flow.
    """

    anomalies = []

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    duration = max(duration, 0.001)

    pps = (
        flow["packetCount"] /
        duration
    )

    if pps > 1000:
        anomalies.append("Packet Rate Spike")

    if flow["retransmissionCount"] >= 10:
        anomalies.append("High Retransmissions")

    if flow["outOfOrderCount"] >= 10:
        anomalies.append("Out-of-Order Packets")

    if flow["maximumJitter"] > 0.05:
        anomalies.append("High Jitter")

    if flow["idleEventCount"] >= 10:
        anomalies.append("Frequent Idle Periods")

    if flow["rstCount"] >= 5:
        anomalies.append("Excessive TCP Resets")

    if duration >= 3600:
        anomalies.append("Long-Lived Flow")

    return {

        "anomalyDetected":
            len(anomalies) > 0,

        "anomalyCount":
            len(anomalies),

        "anomalies":
            anomalies
    }

def analyze_flow_performance(flow):
    """
    Analyze overall flow performance.
    """

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    duration = max(duration, 0.001)

    bytes_per_second = (
        flow["totalBytes"] /
        duration
    )

    packets_per_second = (
        flow["packetCount"] /
        duration
    )

    payload_efficiency = 0.0

    if flow["totalBytes"] > 0:

        payload_efficiency = (
            flow["payloadBytes"] * 100 /
            flow["totalBytes"]
        )

    score = 100.0

    if packets_per_second < 1:
        score -= 20

    if payload_efficiency < 50:
        score -= 20

    if flow["retransmissionCount"] > 0:
        score -= (
            flow["retransmissionCount"] * 2
        )

    if flow["outOfOrderCount"] > 0:
        score -= (
            flow["outOfOrderCount"] * 2
        )

    score = round(
        max(score, 0),
        2
    )

    if score >= 90:
        grade = "Excellent"

    elif score >= 75:
        grade = "Good"

    elif score >= 60:
        grade = "Fair"

    else:
        grade = "Poor"

    return {

        "performanceScore":
            score,

        "performanceGrade":
            grade,

        "bytesPerSecond":
            round(bytes_per_second, 2),

        "packetsPerSecond":
            round(packets_per_second, 2),

        "payloadEfficiency":
            round(payload_efficiency, 2)
    }

def classify_flow(packet, flow):
    """
    Classify overall network flow.
    """

    application = detect_application(packet)

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    duration = max(duration, 0.001)

    packets_per_second = (
        flow["packetCount"] /
        duration
    )

    if application in (
        "DHCP",
        "DNS",
        "NTP",
        "SNMP"
    ):
        return "Control Traffic"

    if application in (
        "mDNS",
        "SSDP",
        "NetBIOS"
    ):
        return "Discovery"

    if application in (
        "FTP",
        "SMB",
        "TFTP"
    ):
        return "File Transfer"

    if application == "RTSP":
        return "Streaming"

    if application in (
        "MQTT",
    ):
        return "Real-Time"

    if packets_per_second >= 500:
        return "Bulk Transfer"

    if packets_per_second <= 5:
        return "Background"

    return "Interactive"

def assess_flow_priority(packet, flow):
    """
    Determine processing priority for a network flow.
    """

    application = detect_application(packet)
    classification = classify_flow(packet, flow)
    state = detect_flow_state(flow)

    if application in (
        "DHCP",
        "DNS",
        "NTP",
        "SNMP"
    ):
        return "Critical"

    if classification in (
        "Real-Time",
        "Streaming"
    ):
        return "High"

    if application in (
        "SSH",
        "RDP",
        "SMB",
        "FTP"
    ):
        return "High"

    if state == "New":
        return "Medium"

    if classification == "Background":
        return "Low"

    return "Medium"

def assess_flow_sla(flow):
    """
    Assess Service Level Agreement (SLA) compliance for a flow.
    """

    score = 100

    if flow["retransmissionCount"] > 0:
        score -= min(flow["retransmissionCount"] * 3, 30)

    if flow["outOfOrderCount"] > 0:
        score -= min(flow["outOfOrderCount"] * 2, 20)

    if flow["maximumJitter"] > 0.05:
        score -= 20

    if flow["idleEventCount"] > 5:
        score -= 10

    score = max(score, 0)

    if score >= 90:
        status = "Excellent"

    elif score >= 75:
        status = "Good"

    elif score >= 50:
        status = "Warning"

    else:
        status = "Critical"

    return {
        "slaScore": score,
        "slaStatus": status,
        "meetsSLA": score >= 75
    }

def analyze_flow_congestion(flow):
    """
    Analyze congestion level of a network flow.
    """

    score = 0

    duration = (
        flow["lastSeen"] -
        flow["firstSeen"]
    )

    duration = max(duration, 0.001)

    packets_per_second = (
        flow["packetCount"] /
        duration
    )

    if packets_per_second > 1000:
        score += 30

    elif packets_per_second > 500:
        score += 15

    score += min(
        flow["retransmissionCount"] * 3,
        30
    )

    score += min(
        flow["outOfOrderCount"] * 2,
        20
    )

    if flow["maximumJitter"] > 0.05:
        score += 10

    average_window = 0

    if flow["windowSamples"] > 0:

        average_window = (
            flow["windowSizeTotal"] /
            flow["windowSamples"]
        )

    if (
        average_window > 0
        and
        average_window < 4096
    ):
        score += 10

    if score >= 60:
        level = "High"

    elif score >= 35:
        level = "Moderate"

    elif score >= 15:
        level = "Low"

    else:
        level = "None"

    return {

        "congestionScore":
            score,

        "congestionLevel":
            level,

        "packetsPerSecond":
            round(packets_per_second, 2),

        "averageWindowSize":
            round(average_window, 2)
    }

def assess_flow_latency(flow):
    """
    Assess latency characteristics of a network flow.
    """

    average_gap = (
        flow["gapTotal"] /
        max(flow["gapCount"], 1)
    )

    average_jitter = (
        flow["jitterTotal"] /
        max(flow["jitterCount"], 1)
    )

    score = 100

    if average_gap > 0.100:
        score -= 25

    elif average_gap > 0.050:
        score -= 10

    if average_jitter > 0.050:
        score -= 25

    elif average_jitter > 0.020:
        score -= 10

    if flow["idleEventCount"] > 5:
        score -= 10

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Fair"

    else:
        level = "Poor"

    return {

        "latencyScore":
            score,

        "latencyLevel":
            level,

        "averageGap":
            round(average_gap, 6),

        "maximumGap":
            round(flow["maxGap"], 6),

        "averageJitter":
            round(average_jitter, 6),

        "maximumJitter":
            round(flow["maximumJitter"], 6)
    }

def assess_network_path_quality(flow):
    """
    Assess overall network path quality.
    """

    average_gap = (
        flow["gapTotal"] /
        max(flow["gapCount"], 1)
    )

    average_jitter = (
        flow["jitterTotal"] /
        max(flow["jitterCount"], 1)
    )

    score = 100

    score -= min(
        flow["retransmissionCount"] * 3,
        30
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    if average_gap > 0.050:
        score -= 15

    if average_jitter > 0.020:
        score -= 15

    if flow["idleEventCount"] > 5:
        score -= 10

    score = max(score, 0)

    if score >= 90:
        quality = "Excellent"

    elif score >= 75:
        quality = "Good"

    elif score >= 50:
        quality = "Fair"

    else:
        quality = "Poor"

    return {

        "pathScore":
            score,

        "pathQuality":
            quality,

        "averageGap":
            round(average_gap, 6),

        "averageJitter":
            round(average_jitter, 6),

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"]
    }

def assess_flow_qos(flow):
    """
    Assess Quality of Service (QoS) for a network flow.
    """

    average_gap = (
        flow["gapTotal"] /
        max(flow["gapCount"], 1)
    )

    average_jitter = (
        flow["jitterTotal"] /
        max(flow["jitterCount"], 1)
    )

    score = 100

    if average_gap > 0.050:
        score -= 20

    if average_jitter > 0.020:
        score -= 20

    score -= min(
        flow["retransmissionCount"] * 3,
        30
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score = max(score, 0)

    if score >= 90:
        qos = "Excellent"

    elif score >= 75:
        qos = "Good"

    elif score >= 50:
        qos = "Fair"

    else:
        qos = "Poor"

    return {

        "qosScore":
            score,

        "qosLevel":
            qos,

        "averageGap":
            round(average_gap, 6),

        "averageJitter":
            round(average_jitter, 6),

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"]
    }

def assess_flow_experience(flow):
    """
    Assess overall end-user experience of a network flow.
    """

    qos = assess_flow_qos(flow)
    latency = assess_flow_latency(flow)
    congestion = analyze_flow_congestion(flow)
    reliability = calculate_flow_reliability(flow)

    score = (
        qos["qosScore"]
        + latency["latencyScore"]
        + reliability["reliabilityPercentage"]
        - congestion["congestionScore"]
    ) / 3

    score = max(0, min(round(score, 2), 100))

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Fair"

    else:
        level = "Poor"

    return {

        "experienceScore":
            score,

        "experienceLevel":
            level,

        "qosScore":
            qos["qosScore"],

        "latencyScore":
            latency["latencyScore"],

        "reliability":
            reliability["reliabilityPercentage"],

        "congestion":
            congestion["congestionScore"]
    }

def assess_flow_service_profile(packet, flow):
    """
    Determine the service profile of a network flow.
    """

    application = detect_application(packet)
    classification = classify_flow(packet, flow)
    priority = assess_flow_priority(packet, flow)
    qos = assess_flow_qos(flow)

    if application in (
        "DHCP",
        "DNS",
        "NTP",
        "SNMP"
    ):
        profile = "Critical Infrastructure"

    elif classification in (
        "Real-Time",
        "Streaming"
    ):
        profile = "Real-Time"

    elif priority == "High":
        profile = "Business"

    elif qos["qosLevel"] in (
        "Excellent",
        "Good"
    ):
        profile = "Standard"

    else:
        profile = "Background"

    return {

        "serviceProfile":
            profile,

        "application":
            application,

        "flowClassification":
            classification,

        "priority":
            priority,

        "qosLevel":
            qos["qosLevel"]
    }

def assess_flow_capacity(flow):
    """
    Assess the capacity utilization of a network flow.
    """

    duration = max(
        flow["lastSeen"] - flow["firstSeen"],
        0.001
    )

    bytes_per_second = (
        flow["totalBytes"] / duration
    )

    packets_per_second = (
        flow["packetCount"] / duration
    )

    payload_efficiency = (
        flow["payloadBytes"] * 100 /
        max(flow["totalBytes"], 1)
    )

    score = 100

    if bytes_per_second < 1000:
        score -= 20

    if packets_per_second < 10:
        score -= 20

    if payload_efficiency < 50:
        score -= 20

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Limited"

    return {

        "capacityScore":
            score,

        "capacityLevel":
            level,

        "bytesPerSecond":
            round(bytes_per_second, 2),

        "packetsPerSecond":
            round(packets_per_second, 2),

        "payloadEfficiency":
            round(payload_efficiency, 2)
    }

def assess_flow_utilization(flow):
    """
    Assess overall utilization of a network flow.
    """

    duration = max(
        flow["lastSeen"] - flow["firstSeen"],
        0.001
    )

    packets_per_second = (
        flow["packetCount"] / duration
    )

    bytes_per_second = (
        flow["totalBytes"] / duration
    )

    payload_efficiency = (
        flow["payloadBytes"] * 100 /
        max(flow["totalBytes"], 1)
    )

    score = 100

    if packets_per_second < 10:
        score -= 20

    if bytes_per_second < 1000:
        score -= 20

    if payload_efficiency < 50:
        score -= 20

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Low"

    return {

        "utilizationScore":
            score,

        "utilizationLevel":
            level,

        "packetsPerSecond":
            round(packets_per_second, 2),

        "bytesPerSecond":
            round(bytes_per_second, 2),

        "payloadEfficiency":
            round(payload_efficiency, 2)
    }

def assess_flow_resources(flow):
    """
    Assess resource consumption of a network flow.
    """

    duration = max(
        flow["lastSeen"] - flow["firstSeen"],
        0.001
    )

    packets_per_second = (
        flow["packetCount"] / duration
    )

    bytes_per_second = (
        flow["totalBytes"] / duration
    )

    average_packet_size = (
        flow["totalBytes"] /
        max(flow["packetCount"], 1)
    )

    payload_efficiency = (
        flow["payloadBytes"] * 100 /
        max(flow["totalBytes"], 1)
    )

    score = 100

    if packets_per_second > 1000:
        score -= 20

    elif packets_per_second > 500:
        score -= 10

    if bytes_per_second > 1000000:
        score -= 20

    elif bytes_per_second > 500000:
        score -= 10

    if average_packet_size > 1400:
        score -= 10

    if payload_efficiency < 50:
        score -= 20

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Heavy"

    return {

        "resourceScore":
            score,

        "resourceLevel":
            level,

        "packetsPerSecond":
            round(packets_per_second, 2),

        "bytesPerSecond":
            round(bytes_per_second, 2),

        "averagePacketSize":
            round(average_packet_size, 2),

        "payloadEfficiency":
            round(payload_efficiency, 2)
    }

def assess_flow_availability(packet, flow):
    """
    Assess the availability of a network flow.
    """

    state = detect_flow_state(flow)

    idle_time = max(
        time.time() - flow["lastSeen"],
        0
    )

    score = 100

    if state == "Idle":
        score -= 20

    elif state == "Closed":
        score -= 50

    score -= min(
        flow["retransmissionCount"] * 3,
        20
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        30
    )

    score = max(score, 0)

    if score >= 90:
        level = "Available"

    elif score >= 70:
        level = "Degraded"

    elif score >= 40:
        level = "Limited"

    else:
        level = "Unavailable"

    return {

        "availabilityScore":
            score,

        "availabilityLevel":
            level,

        "flowState":
            state,

        "idleTime":
            round(idle_time, 2),

        "retransmissions":
            flow["retransmissionCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_resilience(flow):
    """
    Assess the resilience of a network flow.
    """

    score = 100

    score -= min(
        flow["retransmissionCount"] * 3,
        30
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        30
    )

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 10

    elif state == "Closed":
        score -= 20

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Poor"

    return {

        "resilienceScore":
            score,

        "resilienceLevel":
            level,

        "flowState":
            state,

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_continuity(flow):
    """
    Assess the continuity of a network flow.
    """

    score = 100

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 20

    elif state == "Closed":
        score -= 40

    score -= min(
        flow["idleEventCount"] * 3,
        20
    )

    if flow["maximumIdleTime"] > 5:
        score -= 10

    score -= min(
        flow["retransmissionCount"] * 2,
        15
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        20
    )

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Interrupted"

    return {

        "continuityScore":
            score,

        "continuityLevel":
            level,

        "flowState":
            state,

        "idleEvents":
            flow["idleEventCount"],

        "maximumIdleTime":
            round(flow["maximumIdleTime"], 2),

        "retransmissions":
            flow["retransmissionCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_durability(flow):
    """
    Assess the long-term durability of a network flow.
    """

    duration = max(
        flow["lastSeen"] - flow["firstSeen"],
        0.001
    )

    score = 100

    if duration < 5:
        score -= 15

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 10

    elif state == "Closed":
        score -= 25

    score -= min(
        flow["idleEventCount"] * 2,
        15
    )

    score -= min(
        flow["retransmissionCount"] * 2,
        15
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        20
    )

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Fragile"

    return {

        "durabilityScore":
            score,

        "durabilityLevel":
            level,

        "flowDuration":
            round(duration, 2),

        "flowState":
            state,

        "idleEvents":
            flow["idleEventCount"],

        "retransmissions":
            flow["retransmissionCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_robustness(flow):
    """
    Assess the robustness of a network flow.
    """

    score = 100

    score -= min(
        flow["retransmissionCount"] * 2,
        20
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        20
    )

    score -= min(
        flow["idleEventCount"] * 2,
        20
    )

    state = detect_flow_state(flow)

    if state == "Closed":
        score -= 20

    elif state == "Idle":
        score -= 10

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Weak"

    return {

        "robustnessScore":
            score,

        "robustnessLevel":
            level,

        "flowState":
            state,

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "idleEvents":
            flow["idleEventCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_consistency(flow):
    """
    Assess the consistency of a network flow.
    """

    score = 100

    score -= min(
        flow["retransmissionCount"] * 2,
        20
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score -= min(
        flow["idleEventCount"] * 2,
        20
    )

    score -= min(
        int(flow["maximumJitter"] * 100),
        20
    )

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 10

    elif state == "Closed":
        score -= 20

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Poor"

    return {

        "consistencyScore":
            score,

        "consistencyLevel":
            level,

        "flowState":
            state,

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "idleEvents":
            flow["idleEventCount"],

        "maximumJitter":
            round(flow["maximumJitter"], 6)
    }

def assess_flow_recoverability(flow):
    """
    Assess how well a network flow can recover from disruptions.
    """

    score = 100

    score -= min(
        flow["resetTerminationCount"] * 15,
        45
    )

    score -= min(
        flow["retransmissionCount"] * 2,
        20
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        15
    )

    score -= min(
        flow["idleEventCount"] * 3,
        20
    )

    state = detect_flow_state(flow)

    if state == "Closed":
        score -= 10

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Poor"

    return {

        "recoverabilityScore":
            score,

        "recoverabilityLevel":
            level,

        "flowState":
            state,

        "tcpResets":
            flow["resetTerminationCount"],

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "idleEvents":
            flow["idleEventCount"]
    }

def assess_flow_maintainability(flow):
    """
    Assess how easily a network flow can be maintained over time.
    """

    score = 100

    score -= min(
        flow["retransmissionCount"] * 2,
        20
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score -= min(
        flow["idleEventCount"] * 3,
        20
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        30
    )

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 5

    elif state == "Closed":
        score -= 10

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Poor"

    return {

        "maintainabilityScore":
            score,

        "maintainabilityLevel":
            level,

        "flowState":
            state,

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "idleEvents":
            flow["idleEventCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def assess_flow_sustainability(flow):
    """
    Assess the long-term sustainability of a network flow.
    """

    score = 100

    score -= min(
        flow["retransmissionCount"] * 2,
        20
    )

    score -= min(
        flow["outOfOrderCount"] * 2,
        20
    )

    score -= min(
        flow["idleEventCount"] * 2,
        20
    )

    score -= min(
        flow["resetTerminationCount"] * 10,
        30
    )

    state = detect_flow_state(flow)

    if state == "Idle":
        score -= 5

    elif state == "Closed":
        score -= 15

    score = max(score, 0)

    if score >= 90:
        level = "Excellent"

    elif score >= 75:
        level = "Good"

    elif score >= 50:
        level = "Moderate"

    else:
        level = "Poor"

    return {

        "sustainabilityScore":
            score,

        "sustainabilityLevel":
            level,

        "flowState":
            state,

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"],

        "idleEvents":
            flow["idleEventCount"],

        "tcpResets":
            flow["resetTerminationCount"]
    }

def analyze_flow_trend(flow):
    """
    Analyze the overall trend of a network flow.
    """

    duration = max(
        flow["lastSeen"] - flow["firstSeen"],
        0.001
    )

    packets_per_second = (
        flow["packetCount"] / duration
    )

    bytes_per_second = (
        flow["totalBytes"] / duration
    )

    if packets_per_second >= 500:
        trend = "Increasing"

    elif packets_per_second >= 100:
        trend = "Stable"

    else:
        trend = "Decreasing"

    if flow["retransmissionCount"] > 5:
        health = "Degrading"

    elif flow["outOfOrderCount"] > 5:
        health = "Unstable"

    else:
        health = "Healthy"

    return {

        "flowTrend":
            trend,

        "trendHealth":
            health,

        "packetsPerSecond":
            round(packets_per_second, 2),

        "bytesPerSecond":
            round(bytes_per_second, 2),

        "packetCount":
            flow["packetCount"],

        "totalBytes":
            flow["totalBytes"],

        "retransmissions":
            flow["retransmissionCount"],

        "outOfOrderPackets":
            flow["outOfOrderCount"]
    }

def generate_flow_analytics_summary(packet, flow):
    """
    Generate an overall summary of all flow analytics.
    """

    performance = analyze_flow_performance(flow)
    reliability = calculate_flow_reliability(flow)
    stability = calculate_flow_stability(flow)
    qos = assess_flow_qos(flow)
    latency = assess_flow_latency(flow)
    congestion = analyze_flow_congestion(flow)
    experience = assess_flow_experience(flow)
    trend = analyze_flow_trend(flow)
    state = detect_flow_state(flow)

    overall_score = round(
        (
            performance["performanceScore"] +
            reliability["reliabilityPercentage"] +
            stability["stabilityScore"] +
            qos["qosScore"] +
            latency["latencyScore"] +
            experience["experienceScore"]
            - congestion["congestionScore"]
        ) / 6,
        2
    )

    overall_score = max(0, min(overall_score, 100))

    if overall_score >= 90:
        overall_status = "Excellent"

    elif overall_score >= 75:
        overall_status = "Good"

    elif overall_score >= 50:
        overall_status = "Fair"

    else:
        overall_status = "Poor"

    return {

        "overallScore":
            overall_score,

        "overallStatus":
            overall_status,

        "flowState":
            state,

        "flowTrend":
            trend["flowTrend"],

        "performance":
            performance["performanceGrade"],

        "reliability":
            reliability["reliableFlow"],

        "stability":
            stability["stabilityStatus"],

        "qos":
            qos["qosLevel"],

        "latency":
            latency["latencyLevel"],

        "userExperience":
            experience["experienceLevel"],

        "congestion":
            congestion["congestionLevel"]
    }

def detect_flow_state(flow):
    """
    Determine the current state of a flow.
    """

    now = time.time()

    age = now - flow["firstSeen"]
    idle = now - flow["lastSeen"]

    # New Flow
    if age < 2:
        return "New"

    # Closed Flow
    if idle > 120:
        return "Closed"

    # Idle Flow
    if idle > 30:
        return "Idle"

    # Default
    return "Active"

def detect_flow_termination(packet, flow):
    """
    Determine how a flow terminated.
    """

    flags = (packet.get("flags") or "").upper()

    # TCP FIN
    if "FIN" in flags:
        return "TCP FIN"

    # TCP Reset
    if "RST" in flags:
        return "TCP Reset"

    # Timeout
    if detect_flow_state(flow) == "Closed":
        return "Timeout"

    # Still Active
    return "Active"

def assess_flow_risk(packet, flow):
    """
    Assess the security risk of a flow.
    """

    application = detect_application(packet)
    state = detect_flow_state(flow)
    termination = detect_flow_termination(packet, flow)

    # Critical
    if termination == "TCP Reset":
        return "Critical"

    # High
    if application in ("Telnet", "FTP"):
        return "High"

    # Medium
    if application in ("SSH", "RDP", "SMB"):
        return "Medium"

    if state == "Idle":
        return "Medium"

    # Low
    return "Low"

def calculate_flow_health_score(packet, flow):
    """
    Calculate overall health score for a flow.
    """

    score = 100

    state = detect_flow_state(flow)
    termination = detect_flow_termination(packet, flow)
    risk = assess_flow_risk(packet, flow)

    # Flow State
    if state == "Idle":
        score -= 10

    elif state == "Closed":
        score -= 20

    # Termination
    if termination == "TCP Reset":
        score -= 40

    elif termination == "Timeout":
        score -= 20

    # Risk
    if risk == "Medium":
        score -= 15

    elif risk == "High":
        score -= 30

    elif risk == "Critical":
        score -= 50

    return max(0, score)

def generate_flow_summary(packet, flow):
    """
    Generate a concise summary for a flow.
    """

    application = detect_application(packet)
    state = detect_flow_state(flow)
    risk = assess_flow_risk(packet, flow)
    score = calculate_flow_health_score(packet, flow)

    return (
        f"{state} {application} session between "
        f"{flow['sourceIp']} and {flow['destinationIp']} "
        f"({flow['packetCount']} packets, "
        f"{risk} Risk, "
        f"Health Score: {score})"
    )

def analyze_packet_quality(packet):
    """
    Analyze packet size and Ethernet frame quality.
    """

    packet_size = int(
        packet.get("length")
        or packet.get("packetLength")
        or 0
    )

    if packet_size == 0:
        return None

    quality = "Normal"
    frame_type = "Standard Ethernet"

    issues = []

    fragmented = False

    fragment_offset = int(packet.get("fragmentOffset") or 0)

    more_fragments = bool(packet.get("moreFragments") or False)

    padding_detected = False

    padding_bytes = 0

    # Ethernet runt frame
    if packet_size < 64:

        quality = "Poor"
        frame_type = "Runt Frame"

        issues.append("Tiny Ethernet Frame")

    # Standard Ethernet frame
    elif packet_size <= 1518:

        quality = "Normal"
        frame_type = "Standard Ethernet"

    # Jumbo Ethernet frame
    elif packet_size <= 9216:

        quality = "Jumbo Frame"
        frame_type = "Jumbo Ethernet"

    # Oversized Ethernet frame
    else:

        quality = "Oversized"
        frame_type = "Oversized Ethernet"

        issues.append("Frame exceeds Jumbo MTU")

    # Ethernet padding detection
    if 0 < packet_size < 64:

        padding_detected = True
        padding_bytes = 64 - packet_size
        issues.append(f"Ethernet Padding ({padding_bytes} bytes)")

    # IP Fragmentation
    if fragment_offset > 0 or more_fragments:

        fragmented = True
        issues.append("IP Fragmented Packet")

    return {

        "packetSize": packet_size,
        "frameType": frame_type,
        "quality": quality,
        "paddingDetected": padding_detected,
        "paddingBytes": padding_bytes,
        "fragmented": fragmented,
        "fragmentOffset": fragment_offset,
        "moreFragments": more_fragments,
        "issues": issues
    }

def analyze_protocol(packet):
    """
    Analyze protocol-specific information.
    """

    protocol = (packet.get("protocol") or "").upper()

    protocol_map = {
        "TCP": "Transmission Control Protocol",
        "UDP": "User Datagram Protocol",
        "ICMP": "Internet Control Message Protocol",
        "ARP": "Address Resolution Protocol",
        "DNS": "Domain Name System",
        "DHCP": "Dynamic Host Configuration Protocol",
        "HTTP": "Hypertext Transfer Protocol",
        "HTTPS": "Hypertext Transfer Protocol Secure",
        "SSDP": "Simple Service Discovery Protocol",
        "MDNS": "Multicast DNS",
        "NBNS": "NetBIOS Name Service",
        "NTP": "Network Time Protocol",
        "MQTT": "Message Queuing Telemetry Transport"
    }

    return {
        "protocol": protocol,
        "description": protocol_map.get(protocol, "Unknown Protocol")
    }

def analyze_tcp(packet):
    """
    Analyze TCP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "TCP":
        return None

    flags = (packet.get("flags") or "").upper()

    return {
        "flags": {
            "SYN": "SYN" in flags,
            "ACK": "ACK" in flags,
            "FIN": "FIN" in flags,
            "RST": "RST" in flags,
            "PSH": "PSH" in flags,
            "URG": "URG" in flags
        },
        "sequenceNumber": packet.get("sequenceNumber"),
        "acknowledgementNumber": packet.get("acknowledgementNumber"),
        "windowSize": packet.get("windowSize")
    }

def analyze_udp(packet):
    """
    Analyze UDP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "UDP":
        return None

    return {
        "sourcePort": packet.get("sourcePort"),
        "destinationPort": packet.get("destinationPort"),
        "length": packet.get("udpLength") or packet.get("length"),
        "checksum": packet.get("checksum")
    }

def analyze_icmp(packet):
    """
    Analyze ICMP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "ICMP":
        return None

    icmp_type = int(packet.get("icmpType") or -1)
    icmp_code = int(packet.get("icmpCode") or 0)

    descriptions = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem"
    }

    return {
        "type": icmp_type,
        "code": icmp_code,
        "description": descriptions.get(icmp_type, "Other")
    }

def analyze_arp(packet):
    """
    Analyze ARP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "ARP":
        return None

    operation = int(packet.get("arpOperation") or 0)

    operation_name = {
        1: "Request",
        2: "Reply"
    }.get(operation, "Unknown")

    sender_ip = packet.get("arpSenderIp")
    sender_mac = packet.get("arpSenderMac")
    target_ip = packet.get("arpTargetIp")
    target_mac = packet.get("arpTargetMac")

    return {
        "operation": operation_name,
        "senderIp": sender_ip,
        "senderMac": sender_mac,
        "targetIp": target_ip,
        "targetMac": target_mac,
        "gratuitous": sender_ip == target_ip
    }

def analyze_dns(packet):
    """
    Analyze DNS packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "DNS":
        return None

    return {
        "messageType": packet.get("dnsMessageType"),
        "queryName": packet.get("dnsQueryName"),
        "recordType": packet.get("dnsRecordType"),
        "responseCode": packet.get("dnsResponseCode"),
        "answerCount": int(packet.get("dnsAnswerCount") or 0),
        "authorityCount": int(packet.get("dnsAuthorityCount") or 0),
        "additionalCount": int(packet.get("dnsAdditionalCount") or 0)
    }

def analyze_dhcp(packet):
    """
    Analyze DHCP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "DHCP":
        return None

    message_types = {

        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM"
    }

    message_type = message_types.get(
        int(packet.get("dhcpMessageType") or 0),
        "Unknown"
    )

    return {

        "messageType": message_type,
        "transactionId": packet.get("dhcpTransactionId"),
        "clientMac": packet.get("dhcpClientMac"),
        "yourIp": packet.get("dhcpYourIp"),
        "requestedIp": packet.get("dhcpRequestedIp"),
        "serverIp": packet.get("dhcpServerIp"),
        "serverIdentifier": packet.get("dhcpServerIdentifier"),
        "leaseTime": packet.get("dhcpLeaseTime"),
        "renewalTime": packet.get("dhcpRenewalTime"),
        "rebindingTime": packet.get("dhcpRebindingTime"),
        "subnetMask": packet.get("dhcpSubnetMask"),
        "router": packet.get("dhcpRouter"),
        "dnsServers": packet.get("dhcpDnsServers"),
        "domainName": packet.get("dhcpDomainName")
    }

def analyze_dhcp_conversation(packet):
    """
    Track DHCP Discover → Offer → Request → ACK
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "DHCP":
        return None

    transaction_id = packet.get("dhcpTransactionId")

    if not transaction_id:
        return None

    message = packet.get("dhcpMessageType")

    if isinstance(message, str):
        message = message.upper()

    else:

        mapping = {

            1: "DISCOVER",
            2: "OFFER",
            3: "REQUEST",
            5: "ACK",
            6: "NAK",
            7: "RELEASE",
            8: "INFORM"
        }

        message = mapping.get(int(message or 0), "UNKNOWN")

    if transaction_id not in DHCP_CACHE:

        DHCP_CACHE[transaction_id] = {

            "discover": False,
            "offer": False,
            "request": False,
            "ack": False,
            "nak": False
        }

    session = DHCP_CACHE[transaction_id]

    if message == "DISCOVER":
        session["discover"] = True

    elif message == "OFFER":
        session["offer"] = True

    elif message == "REQUEST":
        session["request"] = True

    elif message == "ACK":
        session["ack"] = True

    elif message == "NAK":
        session["nak"] = True

    return {

        "discover": session["discover"],
        "offer": session["offer"],
        "request": session["request"],
        "ack": session["ack"],
        "nak": session["nak"],

        "completed":
            session["discover"]
            and session["offer"]
            and session["request"]
            and session["ack"]
    }

def analyze_dhcp_health(packet):
    """
    Evaluate DHCP negotiation health.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "DHCP":
        return None

    transaction_id = packet.get("dhcpTransactionId")

    if not transaction_id:
        return None

    session = DHCP_CACHE.get(transaction_id)

    if not session:
        return None

    if session["nak"]:

        return {
            "status": "Failed",
            "reason": "DHCP Server rejected the request"
        }

    if (
        session["discover"]
        and session["offer"]
        and session["request"]
        and session["ack"]
    ):

        return {
            "status": "Healthy",
            "reason": "DHCP lease successfully assigned"
        }

    if (
        session["discover"]
        and not session["offer"]
    ):

        return {
            "status": "Warning",
            "reason": "Waiting for DHCP OFFER"
        }

    if (
        session["offer"]
        and not session["request"]
    ):

        return {
            "status": "Warning",
            "reason": "Client has not requested the offered address"
        }

    if (
        session["request"]
        and not session["ack"]
    ):

        return {
            "status": "Warning",
            "reason": "Waiting for DHCP ACK"
        }

    return {
        "status": "In Progress",
        "reason": "DHCP negotiation is ongoing"
    }

def analyze_dhcp_security(packet):
    """
    Analyze DHCP security conditions.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "DHCP":
        return None

    issues = []

    risk = "Low"

    server = packet.get("dhcpServerIdentifier")

    assigned_ip = packet.get("dhcpYourIp")

    lease_time = int(packet.get("dhcpLeaseTime") or 0)

    # Track DHCP Servers
    if server:

        DHCP_SECURITY_CACHE["servers"].add(server)

        if len(DHCP_SECURITY_CACHE["servers"]) > 1:
            issues.append("Multiple DHCP Servers Detected")

    # Duplicate IP Detection
    if assigned_ip:

        previous = DHCP_SECURITY_CACHE["assignedIps"].get(assigned_ip)

        client = packet.get("dhcpClientMac")

        if previous and previous != client:
            issues.append("Duplicate IP Assignment")

        DHCP_SECURITY_CACHE["assignedIps"][assigned_ip] = client

    # Suspicious Lease Time
    if lease_time:

        if lease_time < 300:
            issues.append("Very Short DHCP Lease")

        elif lease_time > 604800:
            issues.append("Very Long DHCP Lease")

    # Risk
    if issues:

        risk = "Medium"

        if (
            "Duplicate IP Assignment" in issues
            or "Multiple DHCP Servers Detected" in issues
        ):
            risk = "High"

    return {

        "risk": risk,

        "issues": issues,

        "dhcpServersSeen":
            len(DHCP_SECURITY_CACHE["servers"])
    }

def analyze_ntp(packet):
    """
    Analyze NTP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "NTP":
        return None

    mode_map = {
        1: "Symmetric Active",
        2: "Symmetric Passive",
        3: "Client",
        4: "Server",
        5: "Broadcast",
        6: "NTP Control",
        7: "Private"
    }

    leap_map = {
        0: "No Warning",
        1: "Last Minute has 61 Seconds",
        2: "Last Minute has 59 Seconds",
        3: "Clock Unsynchronized"
    }

    mode = int(packet.get("ntpMode") or 0)

    leap = int(packet.get("ntpLeapIndicator") or 0)

    return {

        "version": packet.get("ntpVersion"),

        "mode": mode_map.get(mode, "Unknown"),

        "stratum": int(packet.get("ntpStratum") or 0),

        "pollInterval": packet.get("ntpPoll"),

        "precision": packet.get("ntpPrecision"),

        "rootDelay": packet.get("ntpRootDelay"),

        "rootDispersion": packet.get("ntpRootDispersion"),

        "referenceId": packet.get("ntpReferenceId"),

        "leapIndicator": leap_map.get(leap, "Unknown")
    }

def analyze_ntp_health(packet):
    """
    Evaluate NTP synchronization health.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "NTP":
        return None

    stratum = int(packet.get("ntpStratum") or 0)
    leap = int(packet.get("ntpLeapIndicator") or 0)

    root_delay = float(packet.get("ntpRootDelay") or 0)
    root_dispersion = float(packet.get("ntpRootDispersion") or 0)

    issues = []

    status = "Healthy"

    # Unsynchronized Clock
    if leap == 3:
        issues.append("Clock Unsynchronized")

    # Invalid Stratum
    if stratum == 0 or stratum > 15:
        issues.append("Invalid Stratum")

    # High Network Delay
    if root_delay > 1:
        issues.append("High Root Delay")

    # High Clock Dispersion
    if root_dispersion > 1:
        issues.append("High Root Dispersion")

    if issues:

        status = "Warning"

        if (
            "Clock Unsynchronized" in issues
            or "Invalid Stratum" in issues
        ):
            status = "Critical"

    return {

        "status": status,

        "issues": issues,

        "stratum": stratum
    }

def analyze_ntp_security(packet):
    """
    Analyze NTP security conditions.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "NTP":
        return None

    issues = []

    risk = "Low"

    server = packet.get("sourceIp") or packet.get("ntpServerIp")

    reference_id = packet.get("ntpReferenceId")

    mode = int(packet.get("ntpMode") or 0)

    stratum = int(packet.get("ntpStratum") or 0)

    # Track NTP Servers
    if server:

        NTP_SECURITY_CACHE["servers"].add(server)

        if len(NTP_SECURITY_CACHE["servers"]) > 1:
            issues.append("Multiple NTP Servers Detected")

    # Reference Clock Changed
    if reference_id:

        previous = NTP_SECURITY_CACHE["lastReferenceId"]

        if previous and previous != reference_id:
            issues.append("Reference Clock Changed")

        NTP_SECURITY_CACHE["lastReferenceId"] = reference_id

    # Invalid Stratum
    if stratum == 0 or stratum > 15:
        issues.append("Invalid Stratum Server")

    # Broadcast Mode
    if mode == 5:
        issues.append("Broadcast NTP Mode")

    if issues:

        risk = "Medium"

        if (
            "Multiple NTP Servers Detected" in issues
            or "Invalid Stratum Server" in issues
        ):
            risk = "High"

    return {

        "risk": risk,

        "issues": issues,

        "ntpServersSeen":
            len(NTP_SECURITY_CACHE["servers"])
    }

def analyze_snmp(packet):
    """
    Analyze SNMP packet details.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "SNMP":
        return None

    pdu_map = {
        0: "Get Request",
        1: "Get Next Request",
        2: "Get Response",
        3: "Set Request",
        4: "Trap",
        5: "Get Bulk Request",
        6: "Inform Request",
        7: "SNMPv2 Trap",
        8: "Report"
    }

    version_map = {
        0: "SNMPv1",
        1: "SNMPv2c",
        3: "SNMPv3"
    }

    version = int(packet.get("snmpVersion") or -1)

    pdu = int(packet.get("snmpPduType") or -1)

    return {

        "version": version_map.get(version, "Unknown"),

        "community": packet.get("snmpCommunity"),

        "pduType": pdu_map.get(pdu, "Unknown"),

        "requestId": packet.get("snmpRequestId"),

        "errorStatus": packet.get("snmpErrorStatus"),

        "errorIndex": packet.get("snmpErrorIndex"),

        "oid": packet.get("snmpOid"),

        "value": packet.get("snmpValue")
    }

def analyze_snmp_health(packet):
    """
    Evaluate SNMP communication health.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "SNMP":
        return None

    version = int(packet.get("snmpVersion") or -1)

    pdu = int(packet.get("snmpPduType") or -1)

    error_status = int(packet.get("snmpErrorStatus") or 0)

    community = packet.get("snmpCommunity")

    issues = []

    status = "Healthy"

    # Invalid PDU
    if pdu < 0 or pdu > 8:
        issues.append("Unknown PDU Type")

    # SNMP Error
    if error_status != 0:
        issues.append("SNMP Error Returned")

    # Missing Community (SNMPv1/v2c)
    if version in (0, 1):

        if not community:
            issues.append("Missing Community String")

    if issues:

        status = "Warning"

        if "SNMP Error Returned" in issues:
            status = "Critical"

    return {

        "status": status,

        "issues": issues,

        "errorStatus": error_status
    }

def analyze_snmp_security(packet):
    """
    Analyze SNMP security conditions.
    """

    protocol = (packet.get("protocol") or "").upper()

    if protocol != "SNMP":
        return None

    version = int(packet.get("snmpVersion") or -1)

    community = (packet.get("snmpCommunity") or "").lower()

    pdu = int(packet.get("snmpPduType") or -1)

    issues = []

    risk = "Low"

    # Default community strings
    if community in ("public", "private"):
        issues.append("Default Community String")

    # SNMP SET Request
    if pdu == 3:
        issues.append("SNMP SET Operation")

    # Legacy SNMP versions
    if version in (0, 1):
        issues.append("Insecure SNMP Version")

    # Count Trap packets
    if pdu == 4:

        SNMP_SECURITY_CACHE["trapCount"] += 1

        if SNMP_SECURITY_CACHE["trapCount"] > 100:
            issues.append("Excessive SNMP Traps")

    if issues:

        risk = "Medium"

        if (
            "Default Community String" in issues
            or "SNMP SET Operation" in issues
        ):
            risk = "High"

    return {

        "risk": risk,

        "issues": issues,

        "trapCount": SNMP_SECURITY_CACHE["trapCount"]
    }

