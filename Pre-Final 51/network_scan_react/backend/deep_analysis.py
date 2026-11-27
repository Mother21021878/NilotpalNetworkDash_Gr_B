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


    return analysis