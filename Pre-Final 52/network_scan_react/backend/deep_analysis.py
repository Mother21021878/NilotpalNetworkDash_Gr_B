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


    selected_packet = packet_window[
        len(packet_window) // 2
    ]


    context_packets = packet_window


    response = ai_engine.ask(
        selected_packet,
        context_packets
    )


    analysis = json.loads(response)


    if not isinstance(analysis, dict):

        raise ValueError(
            "Deep Analysis returned an invalid JSON object."
        )


    # -------------------------------------------------
    # Normalize risk score
    # -------------------------------------------------

    try:

        analysis["risk_score"] = int(
            float(
                analysis.get(
                    "risk_score",
                    0
                )
            )
        )

    except (TypeError, ValueError):

        analysis["risk_score"] = 0


    analysis["risk_score"] = max(
        0,
        min(
            100,
            analysis["risk_score"]
        )
    )


    # -------------------------------------------------
    # Normalize risk level
    # -------------------------------------------------

    risk_level = str(
        analysis.get(
            "risk_level",
            "UNKNOWN"
        ) or "UNKNOWN"
    ).upper()


    allowed_risk_levels = {

        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN"

    }


    if risk_level not in allowed_risk_levels:

        risk_level = "UNKNOWN"


    analysis["risk_level"] = risk_level


    # -------------------------------------------------
    # Normalize confidence
    # -------------------------------------------------

    try:

        analysis["confidence"] = int(
            float(
                analysis.get(
                    "confidence",
                    0
                )
            )
        )

    except (TypeError, ValueError):

        analysis["confidence"] = 0


    analysis["confidence"] = max(
        0,
        min(
            100,
            analysis["confidence"]
        )
    )


    # -------------------------------------------------
    # Normalize text fields
    # -------------------------------------------------

    analysis["category"] = str(
        analysis.get(
            "category",
            "Network Traffic"
        ) or "Network Traffic"
    )


    analysis["summary"] = str(
        analysis.get(
            "summary",
            ""
        ) or ""
    )


    analysis["reasoning"] = str(
        analysis.get(
            "reasoning",
            ""
        ) or ""
    )


    # -------------------------------------------------
    # Normalize list fields
    # -------------------------------------------------

    analysis["observations"] = normalize_analysis_list(
        analysis.get(
            "observations"
        )
    )


    analysis["patterns"] = normalize_analysis_list(
        analysis.get(
            "patterns"
        )
    )


    analysis["recommendations"] = normalize_analysis_list(
        analysis.get(
            "recommendations"
        )
    )


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