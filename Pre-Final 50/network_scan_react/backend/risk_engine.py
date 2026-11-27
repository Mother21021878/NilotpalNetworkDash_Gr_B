class RiskEngine:

    def calculate(self, packet, category_result):

        score = category_result["baseRisk"]
        protocol = str(packet.get("protocol", "")).upper()
        transport = str(packet.get("transport", "")).upper()
        src_port = str(packet.get("sourcePort", ""))
        dst_port = str(packet.get("destinationPort", ""))
        length = int(packet.get("length", 0) or 0)
        source = str(packet.get("source", "")).strip()
        destination = str(packet.get("destination", "")).strip()

        private = (
            destination.startswith("10.")
            or destination.startswith("172.")
            or destination.startswith("192.168.")
            or destination.lower().startswith("fe80:")
            or destination.lower().startswith("fc")
            or destination.lower().startswith("fd")
        )

        category = "Unknown"

        reasons = []

        # TCP Categories
        if transport == "TCP":

            if "443" in (src_port, dst_port):
                category = "HTTPS"

            elif "80" in (src_port, dst_port):
                category = "HTTP"

            elif "22" in (src_port, dst_port):
                category = "SSH"

            elif "21" in (src_port, dst_port):
                category = "FTP"

            elif "25" in (src_port, dst_port):
                category = "SMTP"

            elif "3389" in (src_port, dst_port):
                category = "RDP"
            else:
                category = "Generic TCP"


        # UDP Categories
        elif transport == "UDP":
            if "53" in (src_port, dst_port):
                category = "DNS"
            elif "67" in (src_port, dst_port) or "68" in (src_port, dst_port):
                category = "DHCP"
            elif "123" in (src_port, dst_port):
                category = "NTP"
            elif "1900" in (src_port, dst_port):
                category = "SSDP"
            elif "5353" in (src_port, dst_port):
                category = "mDNS"
            else:
                category = "Generic UDP"

        else:
            category = transport or protocol or "Unknown"


        if dst_port in ("4444", "5555", "6666", "31337"):
            score += 30
            reasons.append("Suspicious destination port")
        if length > 1400:
            reasons.append("Large packet")
        if category == "FTP":
            reasons.append("Plain text protocol")
        if not private:
            reasons = list(dict.fromkeys(reasons))
            reasons.append("External destination")

        if category == "HTTPS":
            score += 2
        elif category == "HTTP":
            score += 8
        elif category == "FTP":
            score += 20
        elif category == "TELNET":
            score += 25
        elif category == "SSH":
            score += 4
        elif category == "DNS":
            score += 3

        # Large packet
        if length > 1400:
            score += 15

        elif length > 1000:
            score += 8

        # Plain text protocols
        if dst_port in ("21", "23", "20"):
            score += 20

        # Remote access
        if dst_port in ("22", "3389"):
            score += 10
            reasons.append("Remote administration protocol")

        # Unknown protocol
        if protocol == "" or protocol == "DATA":
            score += 15
            reasons.append("Unknown protocol detected")

        if destination and not private:
            score += 5

        # Broadcast
        if destination.endswith(".255"):
            score += 10

        

        if category == "DNS" and length > 1200:
            score += 15
            reasons.append("Unusually large DNS packet")
        if category == "HTTPS" and dst_port == "80":
            score += 25
            reasons.append("HTTPS traffic on unexpected port")
        if category == "RDP" and not private:
            score += 20
            reasons.append("Remote Desktop exposed externally")

        score = max(0, min(score, 100))

        if score <= 20:
            level = "Low"
        elif score <= 50:
            level = "Medium"
        elif score <= 80:
            level = "High"
        else:
            level = "Critical"

        suspicious = score >= 60

        confidence = min(100, 50 + len(reasons) * 10)

        return {
            "category": category,
            "protocol": protocol,
            "transport": transport,
            "riskScore": score,
            "riskLevel": level,
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons
        }

risk_engine = RiskEngine()