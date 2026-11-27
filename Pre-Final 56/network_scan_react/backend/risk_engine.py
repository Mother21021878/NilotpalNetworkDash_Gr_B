class RiskEngine:
    """
    Deterministic packet risk engine with transparent score explainability.
    The rule definitions below are the authoritative packet scoring rules.
    """

    ENGINE_VERSION = "packet-risk-v2"
    EXPLAINABILITY_VERSION = "1.1"
    SCORE_CAP = 100

    RULES = [
        {"ruleId": "PACKET-RISK-PORT-001", "factor": "Suspicious destination port", "severity": "High", "impact": 30},
        {"ruleId": "PACKET-RISK-PROTOCOL-001", "factor": "HTTPS protocol", "severity": "Low", "impact": 2},
        {"ruleId": "PACKET-RISK-PROTOCOL-002", "factor": "HTTP protocol", "severity": "Medium", "impact": 8},
        {"ruleId": "PACKET-RISK-PROTOCOL-003", "factor": "FTP protocol", "severity": "High", "impact": 20},
        {"ruleId": "PACKET-RISK-PROTOCOL-004", "factor": "TELNET protocol", "severity": "High", "impact": 25},
        {"ruleId": "PACKET-RISK-PROTOCOL-005", "factor": "SSH protocol", "severity": "Low", "impact": 4},
        {"ruleId": "PACKET-RISK-PROTOCOL-006", "factor": "DNS protocol", "severity": "Low", "impact": 3},
        {"ruleId": "PACKET-RISK-SIZE-001", "factor": "Large packet", "severity": "Medium", "impact": 15},
        {"ruleId": "PACKET-RISK-SIZE-002", "factor": "Medium packet size", "severity": "Low", "impact": 8},
        {"ruleId": "PACKET-RISK-PLAINTEXT-001", "factor": "Plain text protocol", "severity": "High", "impact": 20},
        {"ruleId": "PACKET-RISK-REMOTE-001", "factor": "Remote administration protocol", "severity": "Medium", "impact": 10},
        {"ruleId": "PACKET-RISK-PROTOCOL-007", "factor": "Unknown protocol", "severity": "Medium", "impact": 15},
        {"ruleId": "PACKET-RISK-EXTERNAL-001", "factor": "External destination", "severity": "Low", "impact": 5},
        {"ruleId": "PACKET-RISK-BROADCAST-001", "factor": "Broadcast destination", "severity": "Medium", "impact": 10},
        {"ruleId": "PACKET-RISK-DNS-001", "factor": "Unusually large DNS packet", "severity": "High", "impact": 15},
        {"ruleId": "PACKET-RISK-HTTPS-001", "factor": "HTTPS traffic on unexpected port", "severity": "High", "impact": 25},
        {"ruleId": "PACKET-RISK-RDP-001", "factor": "Remote Desktop exposed externally", "severity": "High", "impact": 20},
    ]

    def _add_factor(
        self,
        breakdown,
        rule_id,
        factor,
        impact,
        severity,
        evidence,
        source,
        source_field,
        observed_value,
        recommendation,
        running_score,
    ):
        score_before = running_score
        score_after = running_score + impact

        breakdown.append({
            "ruleId": rule_id,
            "factor": factor,
            "evidence": str(evidence),
            "description": str(evidence),
            "impact": impact,
            "scoreBefore": score_before,
            "scoreAfter": score_after,
            "scoreWithoutFactor": None,
            "remediationImpact": -impact,
            "severity": severity,
            "recommendation": recommendation,
            "source": source,
            "sourceField": source_field,
            "observedValue": observed_value,
            "role": "Actual packet risk-score contribution",
        })

        return score_after

    def calculate(self, packet, category_result):
        packet = packet if isinstance(packet, dict) else {}
        category_result = category_result if isinstance(category_result, dict) else {}

        raw_score = int(category_result.get("baseRisk", 0) or 0)
        score = raw_score

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
        breakdown = []

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
            score = self._add_factor(
                breakdown, "PACKET-RISK-PORT-001",
                "Suspicious destination port", 30, "High",
                f"Destination port {dst_port} is classified as suspicious.",
                "packet", "destinationPort", dst_port,
                "Review the destination service and restrict unauthorized access.",
                score
            )
            reasons.append("Suspicious destination port")

        if length > 1400:
            reasons.append("Large packet")
        if category == "FTP":
            reasons.append("Plain text protocol")

        if category == "HTTPS":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-001",
                "HTTPS protocol", 2, "Low",
                "Packet category is HTTPS.",
                "packet", "category", category,
                "Prefer HTTPS for protected application traffic.",
                score
            )
        elif category == "HTTP":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-002",
                "HTTP protocol", 8, "Medium",
                "Packet category is HTTP.",
                "packet", "category", category,
                "Use HTTPS where confidentiality and integrity are required.",
                score
            )
        elif category == "FTP":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-003",
                "FTP protocol", 20, "High",
                "Packet category is FTP.",
                "packet", "category", category,
                "Prefer a secure file-transfer protocol.",
                score
            )
        elif category == "TELNET":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-004",
                "TELNET protocol", 25, "High",
                "Packet category is TELNET.",
                "packet", "category", category,
                "Replace Telnet with SSH where possible.",
                score
            )
        elif category == "SSH":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-005",
                "SSH protocol", 4, "Low",
                "Packet category is SSH.",
                "packet", "category", category,
                "Restrict SSH exposure to authorized sources.",
                score
            )
        elif category == "DNS":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-006",
                "DNS protocol", 3, "Low",
                "Packet category is DNS.",
                "packet", "category", category,
                "Review unusual DNS traffic separately when present.",
                score
            )

        if length > 1400:
            score = self._add_factor(
                breakdown, "PACKET-RISK-SIZE-001",
                "Large packet", 15, "Medium",
                f"Packet length is {length} bytes, greater than 1400.",
                "packet", "length", length,
                "Investigate unusually large packets in the surrounding traffic context.",
                score
            )
        elif length > 1000:
            score = self._add_factor(
                breakdown, "PACKET-RISK-SIZE-002",
                "Medium packet size", 8, "Low",
                f"Packet length is {length} bytes, greater than 1000.",
                "packet", "length", length,
                "Review packet-size patterns if large packets are unexpected.",
                score
            )

        if dst_port in ("21", "23", "20"):
            score = self._add_factor(
                breakdown, "PACKET-RISK-PLAINTEXT-001",
                "Plain text protocol", 20, "High",
                f"Destination port {dst_port} is associated with a plain-text protocol.",
                "packet", "destinationPort", dst_port,
                "Prefer encrypted alternatives.",
                score
            )

        if dst_port in ("22", "3389"):
            score = self._add_factor(
                breakdown, "PACKET-RISK-REMOTE-001",
                "Remote administration protocol", 10, "Medium",
                f"Destination port {dst_port} is associated with remote administration.",
                "packet", "destinationPort", dst_port,
                "Restrict remote administration to authorized sources.",
                score
            )
            reasons.append("Remote administration protocol")

        if protocol == "" or protocol == "DATA":
            score = self._add_factor(
                breakdown, "PACKET-RISK-PROTOCOL-007",
                "Unknown protocol", 15, "Medium",
                "The packet protocol is empty or DATA.",
                "packet", "protocol", protocol,
                "Inspect packet decoding and identify the underlying protocol.",
                score
            )
            reasons.append("Unknown protocol detected")

        if destination and not private:
            score = self._add_factor(
                breakdown, "PACKET-RISK-EXTERNAL-001",
                "External destination", 5, "Low",
                f"Destination {destination} is outside the recognized private/local ranges.",
                "packet", "destination", destination,
                "Review external communication and confirm the destination is authorized.",
                score
            )
            reasons.append("External destination")

        if destination.endswith(".255"):
            score = self._add_factor(
                breakdown, "PACKET-RISK-BROADCAST-001",
                "Broadcast destination", 10, "Medium",
                f"Destination {destination} appears to be a broadcast address.",
                "packet", "destination", destination,
                "Review broadcast traffic volume and necessity.",
                score
            )

        if category == "DNS" and length > 1200:
            score = self._add_factor(
                breakdown, "PACKET-RISK-DNS-001",
                "Unusually large DNS packet", 15, "High",
                f"DNS packet length is {length} bytes, greater than 1200.",
                "packet", "length", length,
                "Investigate unusually large DNS messages and surrounding DNS activity.",
                score
            )
            reasons.append("Unusually large DNS packet")

        if category == "HTTPS" and dst_port == "80":
            score = self._add_factor(
                breakdown, "PACKET-RISK-HTTPS-001",
                "HTTPS traffic on unexpected port", 25, "High",
                "The packet is classified as HTTPS while using destination port 80.",
                "packet", "destinationPort", dst_port,
                "Verify service configuration and protocol classification.",
                score
            )
            reasons.append("HTTPS traffic on unexpected port")

        if category == "RDP" and not private:
            score = self._add_factor(
                breakdown, "PACKET-RISK-RDP-001",
                "Remote Desktop exposed externally", 20, "High",
                f"RDP traffic targets external destination {destination}.",
                "packet", "destination", destination,
                "Restrict externally reachable RDP and use controlled remote access.",
                score
            )
            reasons.append("Remote Desktop exposed externally")

        reasons = list(dict.fromkeys(reasons))

        raw_calculated_score = score
        score = max(0, min(score, self.SCORE_CAP))
        score_cap_applied = raw_calculated_score > self.SCORE_CAP

        for item in breakdown:
            impact = int(item.get("impact", 0) or 0)
            item["scoreWithoutFactor"] = max(
                0,
                min(raw_calculated_score - impact, self.SCORE_CAP)
            )
            item["remediationImpact"] = -impact

        total_breakdown_impact = sum(
            int(item.get("impact", 0) or 0)
            for item in breakdown
        )

        score_reconciliation = (
            "PASS"
            if raw_calculated_score == raw_score + total_breakdown_impact
            else "CHECK"
        )

        if score <= 20:
            level = "Low"
        elif score <= 50:
            level = "Medium"
        elif score <= 80:
            level = "High"
        else:
            level = "Critical"

        suspicious = score >= 60

        evidence_fields = [
            bool(protocol),
            bool(transport),
            bool(src_port),
            bool(dst_port),
            bool(length),
            bool(source),
            bool(destination),
            bool(category),
        ]
        available_evidence = sum(evidence_fields)
        confidence = min(
            100,
            50 + available_evidence * 5
        )

        return {
            "category": category,
            "protocol": protocol,
            "transport": transport,
            "riskScore": score,
            "riskLevel": level,
            "suspicious": suspicious,
            "confidence": confidence,
            "reasons": reasons,
            "rawScore": raw_calculated_score,
            "scoreCap": self.SCORE_CAP,
            "scoreCapApplied": score_cap_applied,
            "breakdown": breakdown,
            "explainability": {
                "version": self.EXPLAINABILITY_VERSION,
                "engineVersion": self.ENGINE_VERSION,
                "summary": (
                    f"The packet received a risk score of {score}/100 "
                    f"from {len(breakdown)} applicable scoring factor(s)."
                ),
                "decision": {
                    "riskScore": score,
                    "riskLevel": level,
                    "confidence": confidence,
                },
                "method": {
                    "type": "Deterministic additive packet risk score",
                    "formula": "baseRisk + sum(applicable rule impacts), capped at 100",
                    "scoreCap": self.SCORE_CAP,
                },
                "calculation": {
                    "baseScore": raw_score,
                    "totalBreakdownImpact": total_breakdown_impact,
                    "rawScore": raw_calculated_score,
                    "finalScore": score,
                    "scoreCap": self.SCORE_CAP,
                    "scoreCapApplied": score_cap_applied,
                    "factorCount": len(breakdown),
                    "evidenceComplete": (
                        available_evidence == len(evidence_fields)
                    ),
                    "reconciliation": score_reconciliation,
                    "formulaTrace": (
                        f"{raw_score} + {total_breakdown_impact} = "
                        f"{raw_calculated_score}; final = "
                        f"min({raw_calculated_score}, {self.SCORE_CAP})"
                    ),
                },
                "factors": breakdown,
                "confidence": {
                    "score": confidence,
                    "base": 50,
                    "availableEvidenceCount": available_evidence,
                    "totalEvidenceCount": len(evidence_fields),
                    "availableEvidenceWeight": available_evidence * 5,
                    "totalEvidenceWeight": len(evidence_fields) * 5,
                    "formula": "50 + (available evidence count × 5)",
                    "evidenceComplete": (
                        available_evidence == len(evidence_fields)
                    ),
                    "summary": (
                        f"Packet confidence is {confidence}% based on "
                        f"{available_evidence} available evidence sources out of "
                        f"{len(evidence_fields)} evaluated evidence sources."
                    ),
                    "calculation": {
                        "baseScore": 50,
                        "availableEvidenceWeight": available_evidence * 5,
                        "totalEvidenceWeight": len(evidence_fields) * 5,
                        "availableEvidenceCount": available_evidence,
                        "totalEvidenceCount": len(evidence_fields),
                        "formula": "50 + (available evidence count × 5)",
                        "maxScore": 100,
                        "finalScore": confidence
                    },
                },
                "ruleCatalog": self.RULES,
                "limitations": [
                    "The explanation reflects deterministic packet rules evaluated for the current packet.",
                    "Only applicable rules are included in the numeric score breakdown.",
                    "Observed packet characteristics are not by themselves proof of malicious activity.",
                ],
            },
        }


risk_engine = RiskEngine()
