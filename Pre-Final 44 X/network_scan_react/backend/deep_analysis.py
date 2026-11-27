import json
from ai_engine import ai_engine
from ai_feedback import (
    get_learning_examples
)


def prepare_packet_context(packet_window):

    context = []

    for pkt in packet_window:

        context.append({

            "packetNumber":
                pkt.get("id"),

            "time":
                pkt.get("time"),

            "protocol":
                pkt.get("protocol"),

            "source":
                pkt.get("source"),

            "destination":
                pkt.get("destination"),

            "length":
                pkt.get("length"),

            "ttl":
                pkt.get("ttl"),

            "info":
                pkt.get("info")

        })

    return json.dumps(
        context,
        indent=2
    )


def build_deep_analysis_prompt(packet_context):

    prompt = f"""
You are a Senior Network Security Engineer.

Analyze the packet conversation below.

The middle packet is the user-selected packet.

The surrounding packets occurred immediately before
and after it.

Perform:

1. Session analysis

2. TCP handshake validation

3. Protocol flow analysis

4. DNS observations

5. TLS observations

6. Packet ordering

7. Retransmission detection

8. Duplicate ACK detection

9. Broadcast / Multicast detection

10. Port scan detection

11. Malware indicators

12. Lateral movement indicators

13. Overall network behaviour

14. Risk Level

15. Confidence

16. Recommendations

Packet Data

{packet_context}

Return JSON only.

"""

    return prompt


def analyze_packet_window(packet_window):

    if not packet_window:

        raise ValueError(
            "Packet window is empty."
        )


    # ---------------------------------------------------------
    # Selected packet
    # ---------------------------------------------------------

    selected_packet = packet_window[
        len(packet_window) // 2
    ]


    # ---------------------------------------------------------
    # Packet context
    # ---------------------------------------------------------

    context_packets = packet_window


    # ---------------------------------------------------------
    # Load historical human feedback
    # ---------------------------------------------------------

    try:

        feedback_examples = (
            get_learning_examples(20, "packet")
        )

    except Exception:

        feedback_examples = []


    # ---------------------------------------------------------
    # AI analysis
    # ---------------------------------------------------------

    response = ai_engine.ask(

        selected_packet,
        context_packets,
        feedback_examples

    )


    # ---------------------------------------------------------
    # Parse AI JSON response
    # ---------------------------------------------------------

    try:

        return json.loads(
            response
        )

    except json.JSONDecodeError:

        return {

            "risk_score": 0,

            "risk_level": "UNKNOWN",

            "confidence": 0,

            "category": "Error",

            "summary":
                "AI returned an invalid JSON response.",

            "reasoning": [],

            "observations": [],

            "patterns": [],

            "recommendations": []

        }