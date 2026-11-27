import json

from ai_engine import ai_engine


def prepare_packet_context(packet_window):

    context = []

    for pkt in packet_window:

        context.append({

            "packetNumber": pkt.get("id"),

            "time": pkt.get("time"),

            "protocol": pkt.get("protocol"),

            "source": pkt.get("source"),

            "destination": pkt.get("destination"),

            "length": pkt.get("length"),

            "ttl": pkt.get("ttl"),

            "info": pkt.get("info")

        })

    return json.dumps(
        context,
        indent=2
    )


def normalize_analysis_list(value):

    if isinstance(value, list):

        return value


    if value is None:

        return []


    if isinstance(value, str):

        value = value.strip()

        if not value:

            return []

        try:

            parsed = json.loads(value)

            if isinstance(parsed, list):

                return parsed

        except Exception:

            pass

        return [value]


    if isinstance(value, dict):

        return [

            f"{key}: {item}"

            for key, item in value.items()

        ]


    return [str(value)]


def analyze_packet_window(packet_window):

    if len(packet_window) == 0:

        raise ValueError(
            "Packet window is empty."
        )

    center_index = len(packet_window) // 2

    selected_packet = packet_window[center_index]

    context_packets = (
        packet_window[max(0, center_index - 2):center_index]
        + packet_window[center_index + 1:center_index + 3]
    )

    response = ai_engine.ask(
        selected_packet,
        context_packets
    )

    analysis = json.loads(response)


    if not isinstance(analysis, dict):
        raise ValueError(
            "Deep Analysis returned an invalid JSON object."
        )

    required_fields = {
        "risk_score",
        "risk_level",
        "confidence",
        "category",
        "summary",
        "reasoning",
        "observations",
        "patterns",
        "recommendations",
    }
    missing_fields = required_fields - set(analysis)
    unexpected_fields = set(analysis) - required_fields

    if missing_fields:
        raise ValueError(
            "Deep Analysis is missing required fields: "
            + ", ".join(sorted(missing_fields))
        )

    if unexpected_fields:
        raise ValueError(
            "Deep Analysis contains unexpected fields: "
            + ", ".join(sorted(unexpected_fields))
        )


    # -------------------------------------------------
    # Validate risk score
    # -------------------------------------------------

    risk_score = analysis.get("risk_score")

    if (
        not isinstance(risk_score, int)
        or isinstance(risk_score, bool)
        or not 0 <= risk_score <= 100
    ):
        raise ValueError("Invalid risk_score returned by AI.")

    analysis["risk_score"] = risk_score


    # -------------------------------------------------
    # Validate risk level and consistency with score
    # -------------------------------------------------

    risk_level = analysis.get("risk_level")

    if not isinstance(risk_level, str):
        raise ValueError("Invalid risk_level returned by AI.")

    risk_level = risk_level.upper()
    allowed_risk_levels = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN",
    }

    if risk_level not in allowed_risk_levels:
        raise ValueError("Invalid risk_level returned by AI.")

    expected_risk_level = (
        "LOW" if analysis["risk_score"] <= 24 else
        "MEDIUM" if analysis["risk_score"] <= 49 else
        "HIGH" if analysis["risk_score"] <= 79 else
        "CRITICAL"
    )

    if risk_level != "UNKNOWN" and risk_level != expected_risk_level:
        raise ValueError("risk_level does not match risk_score.")

    analysis["risk_level"] = risk_level


    # -------------------------------------------------
    # Validate confidence
    # -------------------------------------------------

    confidence = analysis.get("confidence")

    if (
        not isinstance(confidence, int)
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 100
    ):
        raise ValueError("Invalid confidence returned by AI.")

    analysis["confidence"] = confidence


    # -------------------------------------------------
    # Validate text and list fields
    # -------------------------------------------------

    for field in ("category", "summary", "reasoning"):
        if (
            not isinstance(analysis[field], str)
            or not analysis[field].strip()
        ):
            raise ValueError(f"Invalid {field} returned by AI.")

    for field in ("observations", "patterns", "recommendations"):
        if not isinstance(analysis[field], list):
            raise ValueError(f"Invalid {field} returned by AI.")

        if not all(
            isinstance(item, str) and item.strip()
            for item in analysis[field]
        ):
            raise ValueError(f"Invalid item in {field} returned by AI.")


    # -------------------------------------------------
    # Phase C - Deep Analysis Explainability
    # -------------------------------------------------

    explainability_factors = []

    for item in analysis.get("observations", []):
        explainability_factors.append({
            "factor": "Observation",
            "evidence": str(item),
            "impact": 0,
            "severity": "Informational",
            "role": "Contextual evidence used by deep analysis"
        })

    for item in analysis.get("patterns", []):
        explainability_factors.append({
            "factor": "Pattern",
            "evidence": str(item),
            "impact": 0,
            "severity": "Informational",
            "role": "Contextual pattern identified by deep analysis"
        })

    analysis["explainability"] = {
        "version": "1.1",
        "engine": {
            "name": "LLM Deep Analysis",
            "version": "deep-analysis-v1",
            "explainabilityVersion": "1.1"
        },
        "summary": analysis.get(
            "summary",
            ""
        ),
        "method": {
            "type": "LLM contextual packet-window analysis",
            "formula": (
                "LLM evaluation of the selected packet and "
                "surrounding packet context; no deterministic "
                "numeric scoring formula is applied."
            )
        },
        "decision": {
            "riskScore": analysis.get(
                "risk_score",
                0
            ),
            "riskLevel": analysis.get(
                "risk_level",
                "UNKNOWN"
            ),
            "confidence": analysis.get(
                "confidence",
                0
            )
        },
        "scoreExplanation": {
            "riskScore": analysis.get(
                "risk_score",
                0
            ),
            "riskLevel": analysis.get(
                "risk_level",
                "UNKNOWN"
            ),
            "formulaTrace": (
                "Risk score is provided by the LLM deep-analysis "
                "decision and is not calculated by a deterministic "
                "rule engine."
            ),
            "evidenceComplete": bool(
                analysis.get("observations")
                or analysis.get("patterns")
            )
        },
        "factors": explainability_factors,
        "confidence": {
            "score": analysis.get(
                "confidence",
                0
            ),
            "summary": (
                f"Deep analysis confidence is "
                f"{analysis.get('confidence', 0)}% as returned "
                f"by the LLM analysis."
            ),
            "calculation": {
                "type": "LLM-provided confidence",
                "finalScore": analysis.get(
                    "confidence",
                    0
                ),
                "formula": (
                    "Confidence is provided by the LLM; "
                    "no deterministic confidence formula is applied."
                ),
                "maxScore": 100
            },
            "evidenceComplete": bool(
                analysis.get("observations")
                or analysis.get("patterns")
            ),
            "factors": []
        },
        "observations": analysis.get(
            "observations",
            []
        ),
        "patterns": analysis.get(
            "patterns",
            []
        ),
        "recommendations": analysis.get(
            "recommendations",
            []
        ),
        "limitations": [
            "Deep Analysis is generated from the selected packet and surrounding packet context.",
            "The risk score and confidence are LLM-provided values.",
            "The explanation does not represent a deterministic rule-score calculation.",
            "LLM analysis should be interpreted together with deterministic packet risk-engine results."
        ]
    }

    return analysis