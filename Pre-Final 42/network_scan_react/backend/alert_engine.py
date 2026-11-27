import os
import json
import uuid
from datetime import datetime
from threading import Lock
from copy import deepcopy
from risk_engine import risk_engine


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, "pcapCache")

ALERT_HISTORY_FILE = os.path.join(
    CACHE_DIR,
    "alert_history.json"
)

ALERT_RULES_FILE = os.path.join(
    CACHE_DIR,
    "alert_rules.json"
)


alert_lock = Lock()

MAX_ALERT_HISTORY = 1000


DEFAULT_RULES = {
    "high_risk_packet": {
        "enabled": True,
        "severity": "HIGH",
        "threshold": 75
    },

    "critical_risk_packet": {
        "enabled": True,
        "severity": "CRITICAL",
        "threshold": 90
    },

    "suspicious_port": {
        "enabled": True,
        "severity": "HIGH",
        "ports": [
            21,
            23,
            135,
            139,
            445,
            3389
        ]
    },

    "plaintext_protocol": {
        "enabled": True,
        "severity": "MEDIUM",
        "protocols": [
            "HTTP",
            "FTP",
            "TELNET"
        ]
    },

    "high_packet_rate": {
        "enabled": True,
        "severity": "HIGH",
        "packets_per_second": 100
    }
}


def _ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)


def _load_json(path, default):
    _ensure_cache_dir()

    try:
        if not os.path.exists(path):
            return default

        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)

    except Exception:
        return default


def _save_json(path, data):
    _ensure_cache_dir()

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as fp:
        json.dump(
            data,
            fp,
            indent=4
        )


def get_alert_rules():

    with alert_lock:

        stored_rules = _load_json(
            ALERT_RULES_FILE,
            {}
        )

        merged_rules = deepcopy(
            DEFAULT_RULES
        )

        if isinstance(stored_rules, dict):

            for rule_name, rule_value in stored_rules.items():

                if rule_name not in merged_rules:
                    continue

                if isinstance(rule_value, dict):

                    merged_rules[
                        rule_name
                    ].update(
                        rule_value
                    )

        _save_json(
            ALERT_RULES_FILE,
            merged_rules
        )

        return merged_rules


def save_alert_rules(rules):

    if not isinstance(rules, dict):
        raise ValueError(
            "Alert rules must be a JSON object."
        )

    with alert_lock:

        current_rules = _load_json(
            ALERT_RULES_FILE,
            DEFAULT_RULES
        )

        merged_rules = deepcopy(
            DEFAULT_RULES
        )

        if isinstance(current_rules, dict):
            for rule_name, rule_value in current_rules.items():

                if isinstance(rule_value, dict):
                    merged_rules.setdefault(
                        rule_name,
                        {}
                    ).update(rule_value)

        for rule_name, rule_value in rules.items():

            if rule_name not in DEFAULT_RULES:
                continue

            if not isinstance(rule_value, dict):
                continue

            merged_rules[rule_name].update(
                rule_value
            )

        _save_json(
            ALERT_RULES_FILE,
            merged_rules
        )

    return merged_rules


def get_alert_history():
    with alert_lock:
        return _load_json(
            ALERT_HISTORY_FILE,
            []
        )


def _save_alert_history(history):

    if len(history) > MAX_ALERT_HISTORY:
        history = history[
            -MAX_ALERT_HISTORY:
        ]

    with alert_lock:
        _save_json(
            ALERT_HISTORY_FILE,
            history
        )


def _make_alert(
    alert_type,
    severity,
    title,
    message,
    packet=None
):
    packet = packet or {}

    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime(
            "%d-%b-%Y %I:%M:%S %p"
        ),
        "type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "acknowledged": False,

        "packetId": packet.get("id"),
        "source": packet.get("source"),
        "destination": packet.get("destination"),
        "sourcePort": packet.get("sourcePort"),
        "destinationPort": packet.get("destinationPort"),
        "protocol": packet.get("protocol"),

        "riskScore": packet.get("riskScore"),
        "riskLevel": packet.get("riskLevel")
    }


def evaluate_packet(packet, rules):
    alerts = []

    if not packet:
        return alerts

    protocol = str(
        packet.get("protocol") or ""
    ).upper()

    risk_score = packet.get(
        "riskScore"
    )

    # -------------------------------------------------
    # Automatic Risk Evaluation
    # -------------------------------------------------

    if risk_score is None:

        try:

            category_result = {
                "category": packet.get(
                    "category",
                    "Unknown"
                ),
                "baseRisk": 0
            }

            risk_result = risk_engine.calculate(
                packet,
                category_result
            )

            risk_score = risk_result.get(
                "riskScore"
            )

            # Keep the calculated risk information
            # available to the alert engine.
            packet["riskScore"] = risk_result.get(
                "riskScore"
            )

            packet["riskLevel"] = risk_result.get(
                "riskLevel"
            )

            packet["suspicious"] = risk_result.get(
                "suspicious"
            )

        except Exception:
            risk_score = None


    try:

        risk_score = float(
            risk_score
        )

    except (TypeError, ValueError):

        risk_score = None

    high_risk_rule = rules.get(
        "high_risk_packet",
        {}
    )

    critical_rule = rules.get(
        "critical_risk_packet",
        {}
    )


    if (
        critical_rule.get("enabled")
        and risk_score is not None
        and risk_score >= float(
            critical_rule.get(
                "threshold",
                90
            )
        )
    ):

        alerts.append(
            _make_alert(
                "CRITICAL_RISK_PACKET",
                critical_rule.get(
                    "severity",
                    "CRITICAL"
                ),
                "Critical-Risk Packet Detected",
                (
                    f"Packet {packet.get('id')} "
                    f"has critical risk score "
                    f"{risk_score}/100."
                ),
                packet
            )
        )


    elif (
        high_risk_rule.get("enabled")
        and risk_score is not None
        and risk_score >= float(
            high_risk_rule.get(
                "threshold",
                75
            )
        )
    ):

        alerts.append(
            _make_alert(
                "HIGH_RISK_PACKET",
                high_risk_rule.get(
                    "severity",
                    "HIGH"
                ),
                "High-Risk Packet Detected",
                (
                    f"Packet {packet.get('id')} "
                    f"has risk score "
                    f"{risk_score}/100."
                ),
                packet
            )
        )

    # -------------------------------------------------
    # Suspicious Port
    # -------------------------------------------------

    port_rule = rules.get(
        "suspicious_port",
        {}
    )

    suspicious_ports = {
        str(port)
        for port in port_rule.get(
            "ports",
            []
        )
    }

    packet_ports = {
        str(packet.get("sourcePort")),
        str(packet.get("destinationPort"))
    }

    matched_ports = (
        packet_ports &
        suspicious_ports
    )

    if (
        port_rule.get("enabled")
        and matched_ports
    ):
        port = sorted(
            matched_ports
        )[0]

        alerts.append(
            _make_alert(
                "SUSPICIOUS_PORT",
                port_rule.get(
                    "severity",
                    "HIGH"
                ),
                "Suspicious Port Activity",
                (
                    f"Packet {packet.get('id')} "
                    f"uses suspicious port {port}."
                ),
                packet
            )
        )

    # -------------------------------------------------
    # Plain-text Protocol
    # -------------------------------------------------

    plaintext_rule = rules.get(
        "plaintext_protocol",
        {}
    )

    plaintext_protocols = {
        str(protocol).upper()
        for protocol in plaintext_rule.get(
            "protocols",
            []
        )
    }

    if (
        plaintext_rule.get("enabled")
        and protocol in plaintext_protocols
    ):
        alerts.append(
            _make_alert(
                "PLAINTEXT_PROTOCOL",
                plaintext_rule.get(
                    "severity",
                    "MEDIUM"
                ),
                "Plain-Text Protocol Detected",
                (
                    f"{protocol} traffic detected "
                    f"from {packet.get('source')} "
                    f"to {packet.get('destination')}."
                ),
                packet
            )
        )

    return alerts


def evaluate_packet_rate(packets, rule):
    """
    Evaluate packet rate over the most recent time window.

    Returns one alert when the configured packets-per-second
    threshold is exceeded.
    """

    if not rule.get("enabled"):
        return None

    try:
        threshold = float(
            rule.get("packets_per_second", 100)
        )
    except (TypeError, ValueError):
        return None

    if threshold <= 0:
        return None

    if not packets:
        return None

    # -------------------------------------------------
    # Collect valid packet timestamps
    # -------------------------------------------------

    timestamps = []

    for packet in packets:

        timestamp = packet.get("timestamp")

        if timestamp is None:
            continue

        try:
            timestamps.append(
                float(timestamp)
            )
        except (TypeError, ValueError):
            continue

    if len(timestamps) < 2:
        return None

    # -------------------------------------------------
    # Use only the most recent 10-second window
    # -------------------------------------------------

    latest_timestamp = max(timestamps)

    window_start = (
        latest_timestamp - 10.0
    )

    recent_timestamps = [
        timestamp
        for timestamp in timestamps
        if timestamp >= window_start
    ]

    if len(recent_timestamps) < 2:
        return None

    # -------------------------------------------------
    # Calculate packet rate
    # -------------------------------------------------

    first_timestamp = min(
        recent_timestamps
    )

    elapsed = (
        latest_timestamp -
        first_timestamp
    )

    if elapsed <= 0:
        return None

    packet_count = len(
        recent_timestamps
    )

    packets_per_second = (
        packet_count / elapsed
    )

    # -------------------------------------------------
    # Threshold check
    # -------------------------------------------------

    if packets_per_second < threshold:
        return None

    return _make_alert(
        "HIGH_PACKET_RATE",
        rule.get("severity", "HIGH"),
        "High Packet Rate Detected",
        (
            f"Packet rate reached "
            f"{packets_per_second:.2f} packets/sec "
            f"over the most recent 10-second window, "
            f"exceeding the configured threshold of "
            f"{threshold:.2f} packets/sec."
        ),
        packets[-1]
    )


def evaluate_packets(packets):
    rules = get_alert_rules()

    history = get_alert_history()

    existing_keys = {
        (
            str(item.get("packetId")),
            item.get("type")
        )
        for item in history
    }

    new_alerts = []

    # -------------------------------------------------
    # Single-packet alert rules
    # -------------------------------------------------

    for packet in packets:

        packet_alerts = evaluate_packet(
            packet,
            rules
        )

        for alert in packet_alerts:

            key = (
                str(alert.get("packetId")),
                alert.get("type")
            )

            if key in existing_keys:
                continue

            existing_keys.add(key)

            history.append(alert)
            new_alerts.append(alert)

    # -------------------------------------------------
    # High Packet Rate
    # -------------------------------------------------

    packet_rate_rule = rules.get(
        "high_packet_rate",
        {}
    )

    packet_rate_alert = evaluate_packet_rate(
        packets,
        packet_rate_rule
    )

    if packet_rate_alert:

        # Packet-rate alerts are associated with
        # the latest packet in the detected window.

        rate_packet_id = packet_rate_alert.get(
            "packetId"
        )

        rate_key = (
            f"PACKET_RATE:{rate_packet_id}",
            packet_rate_alert.get("type")
        )

        if rate_key not in existing_keys:

            existing_keys.add(rate_key)

            history.append(
                packet_rate_alert
            )

            new_alerts.append(
                packet_rate_alert
            )

    # -------------------------------------------------
    # Save new alerts
    # -------------------------------------------------

    if new_alerts:
        _save_alert_history(history)

    return new_alerts


def acknowledge_alert(alert_id):
    history = get_alert_history()

    changed = False

    for alert in history:

        if alert.get("id") == alert_id:
            alert["acknowledged"] = True
            alert["acknowledgedAt"] = (
                datetime.now().strftime(
                    "%d-%b-%Y %I:%M:%S %p"
                )
            )
            changed = True
            break

    if changed:
        _save_alert_history(history)

    return changed