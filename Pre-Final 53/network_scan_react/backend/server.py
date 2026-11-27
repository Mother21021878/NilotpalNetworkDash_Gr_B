import os
import shutil
import json
import traceback
import threading
import time
import platform
import ipaddress
import hashlib
from collections import Counter, OrderedDict
from copy import deepcopy
from flask_cors import CORS
from flask import Flask, jsonify, request
from groq import RateLimitError
from risk_engine import risk_engine
from scanner import *
from packet_capture import start_capture, get_packets
from datetime import datetime
from threading import Lock
from deep_analysis import analyze_packet_window
from packet_capture import get_packet_context
from statistics import build_statistics
from device_ai_engine import analyze_device as ai_analyze_device
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from network_ai_engine import (
    analyze_network_health,
    analyze_network_intelligence_summary,
    initialize_scan_context
)
from alert_engine import (
    get_alert_rules,
    save_alert_rules,
    get_alert_history,
    evaluate_packets,
    acknowledge_alert,
    clear_alert_history
)

app = Flask(__name__)
CORS(app)

SERVER_START = datetime.now()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TRAFFIC_PCAPTRACE_FOLDER = os.path.join(
    BASE_DIR,
    "pcapTrace"
)

TRAFFIC_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "traffic_analysis.json"
)

TRAFFIC_ANALYSIS_HISTORY = os.path.join(
    BASE_DIR,
    "pcapCache",
    "traffic_history.json"
)

RISK_ANALYSIS_CACHE = os.path.join(
    BASE_DIR,
    "pcapCache",
    "risk_analysis.json"
)

RISK_ANALYSIS_HISTORY = os.path.join(
    BASE_DIR,
    "pcapCache",
    "risk_history.json"
)


latest_devices = []
# hostname_cache = {}
latest_dashboard = {}
last_scan_time = None
last_scan_duration = 0

devices_request_count = 0

device_lock = Lock()

# =========================================================
# Phase C - Batch AI Analysis Optimization
# Device AI result cache
# =========================================================

DEVICE_AI_CACHE_VERSION = "phase-c-batch-v1"

DEVICE_AI_CACHE_MAX = 500

DEVICE_AI_CACHE = OrderedDict()
DEVICE_AI_CACHE_LOCK = Lock()

# Prevent duplicate provider calls for concurrent cache misses with the same key.
DEVICE_AI_INFLIGHT_LOCK = Lock()
DEVICE_AI_INFLIGHT_LOCKS = {}

# Phase C - AI provider request-rate control
AI_MAX_REQUESTS_PER_MINUTE = int(
    os.getenv("AI_MAX_REQUESTS_PER_MINUTE", "30")
)

AI_RATE_LIMIT_COOLDOWN_SECONDS = int(
    os.getenv("AI_RATE_LIMIT_COOLDOWN_SECONDS", "60")
)

if AI_MAX_REQUESTS_PER_MINUTE < 1:
    raise ValueError("AI_MAX_REQUESTS_PER_MINUTE must be at least 1.")

if AI_RATE_LIMIT_COOLDOWN_SECONDS < 1:
    raise ValueError("AI_RATE_LIMIT_COOLDOWN_SECONDS must be at least 1.")

AI_REQUEST_TIMESTAMPS = []
AI_COOLDOWN_UNTIL = 0.0
AI_RATE_LIMIT_LOCK = Lock()


# These are the fields currently consumed by
# device_ai_engine.analyze_device().
DEVICE_AI_FINGERPRINT_FIELDS = (
    "active",
    "category",
    "cdpDeviceId",
    "childCount",
    "connectionType",
    "deviceRiskLevel",
    "deviceRiskReasons",
    "deviceRiskScore",
    "deviceType",
    "deviceRiskBreakdown",
    "deviceRiskRawScore",
    "deviceRiskRuleCatalog",
    "deviceRiskScoreCapApplied",
    "discoverySource",
    "hostname",
    "httpBannerDetected",
    "httpScheme",
    "ip",
    "linkConfidence",
    "lldpSystemName",
    "mac",
    "manufacturer",
    "model",
    "openPorts",
    "operatingSystem",
    "parentLinkType",
    "primaryDiscoveryProtocol",
    "responseTime",
    "services",
    "snmpEnabled",
    "sshBannerDetected",
    "topologyLevel",
    "topologyParentName",
    "topologyPath",
    "topologyRole"
)


def _device_ai_cache_key(device):

    fingerprint_data = {
        field: device.get(field)
        for field in DEVICE_AI_FINGERPRINT_FIELDS
    }

    fingerprint_data["_cacheVersion"] = (
        DEVICE_AI_CACHE_VERSION
    )

    serialized = json.dumps(
        fingerprint_data,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


class LocalAIRateLimitError(Exception):
    """Raised when the server's local AI request limit is reached."""

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = max(1, int(retry_after or 1))


def _wait_for_ai_request_slot():
    """Reserve one provider-request slot using a rolling 60-second window."""
    now = time.monotonic()

    with AI_RATE_LIMIT_LOCK:
        if now < AI_COOLDOWN_UNTIL:
            retry_after = int(AI_COOLDOWN_UNTIL - now + 0.999)
            raise LocalAIRateLimitError(
                "AI provider cooldown is active.",
                retry_after=retry_after
            )

        cutoff = now - 60
        AI_REQUEST_TIMESTAMPS[:] = [
            timestamp
            for timestamp in AI_REQUEST_TIMESTAMPS
            if timestamp > cutoff
        ]

        if len(AI_REQUEST_TIMESTAMPS) >= AI_MAX_REQUESTS_PER_MINUTE:
            oldest_timestamp = min(AI_REQUEST_TIMESTAMPS)
            retry_after = max(
                1,
                int(60 - (now - oldest_timestamp) + 0.999)
            )
            raise LocalAIRateLimitError(
                "Local AI request limit reached.",
                retry_after=retry_after
            )

        AI_REQUEST_TIMESTAMPS.append(now)


def _record_ai_provider_rate_limit(ex):
    """Activate cooldown after provider throttling."""
    global AI_COOLDOWN_UNTIL

    headers = getattr(
        getattr(ex, "response", None),
        "headers",
        {}
    ) or {}

    retry_after_value = headers.get("Retry-After")
    cooldown = AI_RATE_LIMIT_COOLDOWN_SECONDS

    if retry_after_value is not None:
        try:
            cooldown = max(1, int(float(retry_after_value)))
        except (TypeError, ValueError):
            try:
                retry_time = parsedate_to_datetime(retry_after_value)

                if retry_time.tzinfo is None:
                    retry_time = retry_time.replace(tzinfo=timezone.utc)

                cooldown = max(
                    1,
                    int(
                        (
                            retry_time
                            - datetime.now(timezone.utc)
                        ).total_seconds()
                    )
                )
            except (TypeError, ValueError, OverflowError):
                cooldown = AI_RATE_LIMIT_COOLDOWN_SECONDS

    with AI_RATE_LIMIT_LOCK:
        AI_COOLDOWN_UNTIL = max(
            AI_COOLDOWN_UNTIL,
            time.monotonic() + cooldown
        )

    return cooldown


def _rate_limited_response(message, retry_after, code="AI_RATE_LIMITED"):
    response = jsonify({
        "status": "ERROR",
        "code": code,
        "message": message
    })
    response.status_code = 429
    response.headers["Retry-After"] = str(max(1, int(retry_after or 1)))
    return response


def _analyze_device_cached(device):
    cache_key = _device_ai_cache_key(device)

    with DEVICE_AI_CACHE_LOCK:
        cached = DEVICE_AI_CACHE.get(cache_key)
        if cached is not None:
            DEVICE_AI_CACHE.move_to_end(cache_key)
            return deepcopy(cached), True

    # Track both the active caller and waiters so lock entries can be safely
    # removed when no request is using that fingerprint.
    with DEVICE_AI_INFLIGHT_LOCK:
        entry = DEVICE_AI_INFLIGHT_LOCKS.get(cache_key)
        if entry is None:
            entry = {"lock": Lock(), "users": 0}
            DEVICE_AI_INFLIGHT_LOCKS[cache_key] = entry
        entry["users"] += 1
        analysis_lock = entry["lock"]

    try:
        with analysis_lock:
            # Another request may have populated the cache while we waited.
            with DEVICE_AI_CACHE_LOCK:
                cached = DEVICE_AI_CACHE.get(cache_key)
                if cached is not None:
                    DEVICE_AI_CACHE.move_to_end(cache_key)
                    return deepcopy(cached), True

            analysis = ai_analyze_device(device)

            if not isinstance(analysis, dict):
                raise TypeError(
                    "Device AI engine must return a dictionary."
                )

            if (
                analysis.get("status") == "ERROR"
                or analysis.get("category") == "Error"
            ):
                raise RuntimeError(
                    analysis.get("message")
                    or analysis.get("summary")
                    or "Device AI analysis failed."
                )

            # The AI engine owns the explanation. The server only supplies
            # a compatibility fallback for incomplete/legacy results.
            analysis["explainability"] = _device_explainability_from_analysis(
                analysis
            )

            with DEVICE_AI_CACHE_LOCK:
                DEVICE_AI_CACHE[cache_key] = deepcopy(analysis)
                DEVICE_AI_CACHE.move_to_end(cache_key)

                while len(DEVICE_AI_CACHE) > DEVICE_AI_CACHE_MAX:
                    DEVICE_AI_CACHE.popitem(last=False)

            return deepcopy(analysis), False
    finally:
        with DEVICE_AI_INFLIGHT_LOCK:
            entry["users"] -= 1
            if entry["users"] == 0:
                DEVICE_AI_INFLIGHT_LOCKS.pop(cache_key, None)


SCAN_INTERVAL = 1800
API_VERSION = "1.0.0"

HOST = "127.0.0.1"
PORT = 5000
API_VERSION = "1.0.0"
BUILD_VERSION = "2026-07-06"

ENABLE_BACKGROUND_SCAN = True
ENABLE_PACKET_CAPTURE = True

"""
def get_hostname_from_ip(ip):

    for device in latest_devices:

        if device.get("ip") == ip:

            hostname = (
                device.get("hostname")
                or device.get("deviceName")
                or "-"
            )

            return hostname

    return "-"
"""

def build_dashboard_summary(devices):

    summary = {

        "totalDevices": 0,
        "onlineDevices": 0,
        "offlineDevices": 0,
        "routers": 0,
        "switches": 0,
        "servers": 0,
        "workstations": 0,
        "printers": 0,
        "iotDevices": 0,
        "criticalRisk": 0,
        "highRisk": 0,
        "mediumRisk": 0,
        "lowRisk": 0,
        "scanDuration": "",
        "lastScanTime": ""
    }

    if not devices:
        return summary

    summary["totalDevices"] = len(devices)

    for device in devices:

        if device.get("active"):
            summary["onlineDevices"] += 1
        else:
            summary["offlineDevices"] += 1

        dtype = (
            device.get("deviceType") or ""
        ).lower()

        if "router" in dtype: summary["routers"] += 1

        elif "switch" in dtype: summary["switches"] += 1

        elif "server" in dtype: summary["servers"] += 1

        elif "printer" in dtype: summary["printers"] += 1

        elif ( "pc" in dtype or "laptop" in dtype or "desktop" in dtype or "windows" in dtype or "linux" in dtype ):
            summary["workstations"] += 1

        else:
            summary["iotDevices"] += 1

        risk = device.get("deviceRiskLevel", "")

        if risk == "Critical": summary["criticalRisk"] += 1

        elif risk == "High": summary["highRisk"] += 1

        elif risk == "Medium": summary["mediumRisk"] += 1

        else:
            summary["lowRisk"] += 1

    summary["scanDuration"] = devices[0].get("scanDuration", "")
    summary["lastScanTime"] = last_scan_time

    return summary

def sort_devices(devices):

    devices.sort(
        key=lambda d: tuple(
            map(
                int,
                d["ip"].split(".")
            )
        )
    )

    return devices

def perform_network_scan():

    start = time.time()
    devices = scan_network() or []
    devices = sort_devices(devices)
    scan_time = datetime.now().strftime("%d-%b-%Y %I:%M:%S %p")
    duration = round(time.time() - start, 2)

    return devices, scan_time, duration

# Initial device scan
try:
    with device_lock:

        latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
        latest_dashboard = build_dashboard_summary(latest_devices)
    
except Exception as e:
    print(f"Initial network scan failed: {e}")
    print(f"[{datetime.now()}] Scan failed: {e}")
    traceback.print_exc()
    latest_devices = []
    last_scan_time = None
    latest_dashboard = build_dashboard_summary([])

# Live Packet Capture API
# Returns the most recently captured network packets.
@app.route("/packets")
def packets():

    try:
        packets = get_packets()

        return jsonify({
            "status":"SUCCESS",
            "count":len(packets),
            "packets":packets
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

# Phase 16 - Real-Time Alerts
@app.route("/alerts", methods=["GET"])
def get_alerts():
    try:
        packets = get_packets()

        # Evaluate current live packets
        evaluate_packets(packets)

        history = get_alert_history()

        return jsonify({
            "status": "SUCCESS",
            "count": len(history),
            "alerts": history
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route("/alerts/rules", methods=["GET"])
def get_alert_rules_api():
    try:
        return jsonify({
            "status": "SUCCESS",
            "rules": get_alert_rules()
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route("/alerts/rules", methods=["PUT"])
def update_alert_rules():
    try:
        rules = request.get_json(
            silent=True
        ) or {}

        saved_rules = save_alert_rules(
            rules
        )

        return jsonify({
            "status": "SUCCESS",
            "rules": saved_rules
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route("/alerts/<alert_id>/ack", methods=["POST"])
def acknowledge_alert_api(alert_id):
    try:
        updated = acknowledge_alert(
            alert_id
        )

        if not updated:
            return jsonify({
                "status": "ERROR",
                "message": "Alert not found."
            }), 404

        return jsonify({
            "status": "SUCCESS",
            "message": "Alert acknowledged."
        })

    except Exception as e:
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

@app.route("/alerts", methods=["DELETE"])
def clear_alerts():

    try:
        packets = get_packets()

        clear_alert_history(
            packets
        )

        return jsonify({
            "status": "SUCCESS",
            "message": "Alert history cleared."
        })

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

# Health Check API
@app.route("/")
def home():

    uptime = datetime.now() - SERVER_START

    with device_lock:
        device_count = len(latest_devices)
        scan_time = last_scan_time

    return jsonify({
        "status": "UP",
        "service": "Network Monitoring API",
        "version": API_VERSION,
        "message": "API Server is running successfully.",
        "uptime": str(uptime).split(".")[0],
        "host": HOST,
        "port": PORT,
        "scanInterval": SCAN_INTERVAL,
        "lastScan": scan_time,
        "deviceCount": device_count,
        "apis": [
            "/scan",
            "/devices",
            "/statistics",
            "/packets",
            "/device/<ip>",
            "/traffic-analysis",
            "/risk-analysis",
            "/alerts",
            "/alerts/rules",
            "/alerts/<alert_id>/ack",
            "/device-security-correlation",
            "/security-report",
            "/dashboard-ai-insights",
            "/ai/analyze_packet",
            "/ping",
            "/version"
        ]
    })

def build_devices_response():

    dashboard = latest_dashboard or build_dashboard_summary(
        latest_devices
    )

    return {
        "status": "SUCCESS",
        "count": len(latest_devices),
        "scanTime": last_scan_time,
        "duration": last_scan_duration,
        "dashboard": dashboard,
        "devices": latest_devices
    }

# Dashboard AI Insights API
@app.route("/dashboard-ai-insights", methods=["GET"])
def dashboard_ai_insights():

    try:

        with device_lock:
            devices = list(latest_devices)

        if not devices:

            return jsonify({
                "status": "ERROR",
                "message": "No devices available for AI insights."
            }), 400

        traffic = {}

        risk = {}

        if os.path.exists(
            TRAFFIC_ANALYSIS_CACHE
        ):
            try:
                with open(
                    TRAFFIC_ANALYSIS_CACHE,
                    "r",
                    encoding="utf-8"
                ) as fp:
                    traffic = json.load(fp)
            except Exception:
                traffic = {}

        if os.path.exists(
            RISK_ANALYSIS_CACHE
        ):
            try:
                with open(
                    RISK_ANALYSIS_CACHE,
                    "r",
                    encoding="utf-8"
                ) as fp:
                    risk = json.load(fp)
            except Exception:
                risk = {}

        initialize_scan_context(
            devices,
            traffic=traffic,
            risk=risk
        )

        summary = analyze_network_intelligence_summary(
            devices
        )

        return jsonify({
            "status": "SUCCESS",
            "summary": summary,
            "generated": datetime.now().strftime(
                "%d-%b-%Y %H:%M:%S"
            )
        })

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

# Scan Network API
@app.route('/scan', methods=['GET'])
def scan():

    global latest_devices, last_scan_time, last_scan_duration

    try:
        with device_lock:
            latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
            global latest_dashboard

            latest_dashboard = build_dashboard_summary(
                latest_devices
            )
            duration = last_scan_duration

        return jsonify(
            build_devices_response()
        )

    except Exception as e:
        print(f"[{datetime.now()}] Scan failed: {e}")
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(e)
        }), 500

# Get Devices API
# Returns the list of devices discovered during the most recent network scan.
# Each device includes details such as IP address, MAC address, hostname,
# device name, model, and other available information.
@app.route('/devices', methods=['GET'])
def get_devices():

    global devices_request_count

    devices_request_count += 1

    print(
        f"[DEVICES #{devices_request_count}] "
        f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} "
        f"client={request.remote_addr} "
        f"referer={request.headers.get('Referer')}"
    )

    with device_lock:

        return jsonify(
            build_devices_response()
        )

# Create Device API
# Creates a new device entry.
# Accepts device information in JSON format through the request body
# and returns a confirmation message along with the received data.
@app.route('/device', methods=['POST'])
def create_device():

    data = request.json

    return jsonify({
        "status":"SUCCESS",
        "message":"Device Created",
        "device":data
    })

def _safe_int(value, default=0):
    """
    Safely convert a value to int without allowing malformed API
    input to break an analysis request.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _device_explainability_from_analysis(analysis):
    """
    Return the authoritative device AI explainability.

    The device_ai_engine is the source of truth.  The server only
    supplies a compatibility fallback when an older/partial engine
    result does not contain explainability.
    """
    if not isinstance(analysis, dict):
        analysis = {}

    explainability = analysis.get("explainability")

    if isinstance(explainability, dict):
        return deepcopy(explainability)

    return build_ai_explainability(
        analysis.get("device", {}),
        analysis
    )


def build_ai_explainability(device, analysis):
    """
    Compatibility fallback for older/partial device AI results.

    IMPORTANT:
    - Never recalculate the device risk score here.
    - Never invent numeric factor impacts.
    - Prefer the exact securityScoreBreakdown returned by
      device_ai_engine/device_risk.
    """
    if not isinstance(device, dict):
        device = {}

    if not isinstance(analysis, dict):
        analysis = {}

    risk_score = _safe_int(
        analysis.get("riskScore"),
        0
    )

    risk_level = (
        analysis.get("riskLevel")
        or "Low"
    )

    confidence = analysis.get(
        "confidence"
    )

    security_score_breakdown = (
        analysis.get("securityScoreBreakdown")
        or []
    )

    factors = []

    if isinstance(security_score_breakdown, list):
        for item in security_score_breakdown:
            if not isinstance(item, dict):
                continue

            # Preserve every explainability field already supplied by
            # the authoritative device risk engine.
            factor = dict(item)

            factor.setdefault(
                "factor",
                "Security Factor"
            )
            factor.setdefault(
                "evidence",
                factor.get("description", "-")
            )
            factor.setdefault(
                "impact",
                0
            )
            factor.setdefault(
                "severity",
                "Low"
            )
            factor.setdefault(
                "role",
                "Actual device risk-score contribution"
            )

            factors.append(factor)

    # General evidence is deliberately kept separate from numeric
    # score contributions.
    if not factors:
        risk_indicators = (
            analysis.get("riskIndicators")
            or []
        )

        attack_surface = (
            analysis.get("attackSurface")
            or []
        )

        reasons = (
            analysis.get("reasons")
            or []
        )

        for item in risk_indicators[:10]:
            factors.append({
                "factor": "Risk Indicator",
                "evidence": str(item),
                "impact": 0,
                "severity": "Informational",
                "role": "Contributing security evidence"
            })

        for item in attack_surface[:10]:
            factors.append({
                "factor": "Attack Surface",
                "evidence": str(item),
                "impact": 0,
                "severity": "Informational",
                "role": "Observed exposed service or surface"
            })

        for item in reasons[:10]:
            factors.append({
                "factor": "Security Finding",
                "evidence": str(item),
                "impact": 0,
                "severity": "Informational",
                "role": "Observed finding used in the assessment"
            })

    if not factors:
        factors.append({
            "factor": "Available Device Evidence",
            "evidence": (
                "No significant risk indicators, findings, "
                "or score contributions were returned."
            ),
            "impact": 0,
            "severity": "Informational",
            "role": "No additional risk evidence identified"
        })

    actual_score_factors = [
        factor
        for factor in factors
        if factor.get("role") in (
            "Actual device risk-score contribution",
            "Actual risk-score contribution"
        )
    ]

    score_explanation = (
        analysis.get("scoreExplanation")
        if isinstance(
            analysis.get("scoreExplanation"),
            dict
        )
        else {}
    )

    calculation = (
        analysis.get("explainability", {}).get("calculation")
        if isinstance(
            analysis.get("explainability"),
            dict
        )
        else None
    )

    if not isinstance(calculation, dict):
        calculation = {
            "rawScore": analysis.get(
                "deviceRiskRawScore",
                risk_score
            ),
            "finalScore": risk_score,
            "scoreCap": analysis.get(
                "deviceRiskScoreCap",
                100
            ),
            "scoreCapApplied": analysis.get(
                "deviceRiskScoreCapApplied",
                False
            ),
            "factorCount": len(actual_score_factors),
            "totalBreakdownImpact": sum(
                _safe_int(
                    factor.get("impact"),
                    0
                )
                for factor in actual_score_factors
            ),
            "evidenceComplete": bool(
                actual_score_factors
            )
        }

    if actual_score_factors:
        summary = (
            f"The AI classified this device as {risk_level} risk "
            f"with a score of {risk_score}/100. "
            f"The displayed score is supported by "
            f"{len(actual_score_factors)} actual risk-score "
            f"contribution(s) from the device risk engine."
        )
    else:
        summary = (
            f"The AI classified this device as {risk_level} risk "
            f"with a score of {risk_score}/100. "
            f"Observable security evidence was returned, but "
            f"no numeric risk-score breakdown was available."
        )

    rule_catalog = (
        analysis.get("deviceRiskRuleCatalog")
        or score_explanation.get("ruleCatalog")
        or {}
    )

    return {
        "version": analysis.get(
            "deviceRiskExplainabilityVersion",
            "1.1"
        ),
        "engine": {
            "name": "Device AI Engine",
            "version": "device-ai-v2",
            "explainabilityVersion": analysis.get(
                "deviceRiskExplainabilityVersion",
                "1.1"
            ),
            "riskEngine": "device-risk-v2"
        },
        "engineVersion": "device-risk-v2",
        "summary": summary,
        "method": {
            "type": "Deterministic device risk rules",
            "formula": (
                "rawScore = sum(applicable rule impacts); "
                "finalScore = min(rawScore, scoreCap)"
            ),
            "scoreCap": calculation.get(
                "scoreCap",
                100
            )
        },
        "decision": {
            "riskLevel": risk_level,
            "riskScore": risk_score,
            "confidence": confidence
        },
        "calculation": calculation,
        "scoreExplanation": score_explanation,
        "factors": factors,
        "confidence": {
            "score": confidence,
            "summary": analysis.get(
                "confidenceSummary",
                ""
            ),
            "calculation": {
                "baseScore": 50,
                "availableEvidenceCount": sum(
                    1
                    for item in (
                        analysis.get(
                            "confidenceExplanation",
                            []
                        )
                        or []
                    )
                    if isinstance(item, dict)
                    and item.get("evidenceAvailable")
                ),
                "totalEvidenceCount": len(
                    analysis.get(
                        "confidenceExplanation",
                        []
                    )
                    or []
                ),
                "formula": (
                    "baseScore + sum(weight for available evidence)"
                ),
                "finalScore": confidence,
                "maxScore": 100
            },
            "evidenceComplete": (
                bool(
                    analysis.get(
                        "confidenceExplanation",
                        []
                    )
                )
                and all(
                    isinstance(item, dict)
                    and item.get("evidenceAvailable") is True
                    for item in (
                        analysis.get(
                            "confidenceExplanation",
                            []
                        )
                        or []
                    )
                )
            ),
            "factors": analysis.get(
                "confidenceExplanation",
                []
            ) or []
        },
        "ruleCatalog": rule_catalog,
        "observations": {
            "riskIndicators": analysis.get(
                "riskIndicators",
                []
            ),
            "attackSurface": analysis.get(
                "attackSurface",
                []
            ),
            "reasons": analysis.get(
                "reasons",
                []
            )
        },
        "recommendations": analysis.get(
            "recommendations",
            []
        ),
        "limitations": [
            "The explanation reflects the risk rules and evidence available during the current device analysis.",
            "The displayed risk score is generated by the device risk engine.",
            "Only detected or applicable risk factors are numeric score contributions.",
            "General security evidence without a numeric contribution is not treated as a score contribution.",
            "This server fallback is used only when the authoritative device AI engine explanation is unavailable."
        ]
    }


def build_packet_ai_explainability(packet, risk_result):
    """
    Return the authoritative packet risk-engine explainability.

    The server must never rebuild, reinterpret, or downgrade the
    packet risk-engine explanation.
    """
    if not isinstance(risk_result, dict):
        risk_result = {}

    explainability = risk_result.get(
        "explainability"
    )

    if isinstance(explainability, dict):
        return deepcopy(explainability)

    return {
        "version": "1.1",
        "engineVersion": "packet-risk-v2",
        "summary": (
            "Packet explainability was not returned by the "
            "packet risk engine."
        ),
        "decision": {
            "riskScore": risk_result.get(
                "riskScore",
                risk_result.get("score", 0)
            ),
            "riskLevel": risk_result.get(
                "riskLevel",
                risk_result.get("level", "Unknown")
            ),
            "confidence": risk_result.get(
                "confidence",
                0
            )
        },
        "method": {
            "type": "Unavailable",
            "formula": "Unavailable"
        },
        "calculation": {
            "factorCount": 0,
            "evidenceComplete": False
        },
        "factors": [],
        "ruleCatalog": {},
        "limitations": [
            "Authoritative packet risk-engine explainability was unavailable."
        ]
    }


@app.route("/device-ai-analysis", methods=["POST"])
def device_ai_analysis():
    device = request.get_json(silent=True) or {}

    if not isinstance(device, dict):
        return jsonify({
            "status": "ERROR",
            "message": "Request body must be a JSON object."
        }), 400

    try:
        result, cache_hit = _analyze_device_cached(device)
        return jsonify(result), 200

    except Exception:
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": "Device AI analysis failed."
        }), 500

@app.route("/device-ai-analysis-batch", methods=["POST"])
def device_ai_analysis_batch():

    batch_start = time.perf_counter()

    try:

        data = request.get_json(silent=True) or {}

        devices = data.get("devices", [])

        if not isinstance(devices, list):

            return jsonify({
                "status": "ERROR",
                "message": "devices must be an array."
            }), 400

        if not devices:
            return jsonify({
                "status": "ERROR",
                "message": "At least one device is required."
            }), 400


        results = []
        failed = []

        # -------------------------------------------------
        # Remove duplicate devices from the request
        # -------------------------------------------------

        unique_devices = []

        seen = set()

        for device in devices:

            if not isinstance(device, dict):
                failed.append({
                    "endpointId": "",
                    "ip": "",
                    "hostname": "",
                    "error": "Each device entry must be a JSON object."
                })
                continue

            device_key = (
                device.get("endpointId")
                or device.get("ip")
                or device.get("mac")
                or device.get("hostname")
            )

            if not device_key:
                failed.append({
                    "endpointId": "",
                    "ip": device.get("ip", ""),
                    "hostname": device.get("hostname", ""),
                    "error": "Device requires endpointId, ip, mac, or hostname."
                })
                continue

            device_key = str(device_key).strip().lower()

            if device_key in seen:
                continue

            seen.add(device_key)
            unique_devices.append(device)

        # -------------------------------------------------
        # Phase C - Cached batch AI analysis
        # -------------------------------------------------

        cache_hits = 0
        computed = 0

        for device in unique_devices:

            try:

                analysis, cache_hit = (
                    _analyze_device_cached(
                        device
                    )
                )

                if cache_hit:
                    cache_hits += 1
                else:
                    computed += 1


                results.append({

                    "endpointId":
                        device.get(
                            "endpointId",
                            ""
                        ),

                    "ip":
                        device.get(
                            "ip",
                            ""
                        ),

                    "hostname":
                        device.get(
                            "hostname",
                            ""
                        ),

                    "analysis":
                        analysis,

                    "cacheHit":
                        cache_hit

                })

            
            except Exception as ex:
                failed.append({
                    "endpointId": device.get("endpointId", ""),
                    "ip": device.get("ip", ""),
                    "hostname": device.get("hostname", ""),
                    "error": str(ex)
                })


        duration_ms = round(
            (
                time.perf_counter()
                - batch_start
            ) * 1000,
            2
        )

        if not results and failed:
            return jsonify({
                "status": "ERROR",
                "message": "All device AI analyses failed.",
                "totalRequested": len(devices),
                "uniqueDevices": len(unique_devices),
                "totalAnalyzed": 0,
                "totalComputed": computed,
                "cacheHits": cache_hits,
                "totalFailed": len(failed),
                "durationMs": duration_ms,
                "results": results,
                "failed": failed
            }), 502

        return jsonify({

            "status":
                "SUCCESS",

            "totalRequested":
                len(devices),

            "uniqueDevices":
                len(unique_devices),

            "totalAnalyzed":
                len(results),

            "totalComputed":
                computed,

            "cacheHits":
                cache_hits,

            "totalFailed":
                len(failed),

            "durationMs":
                duration_ms,

            "results":
                results,

            "failed":
                failed

        })


    except Exception as ex:

        traceback.print_exc()

        return jsonify({

            "status":
                "ERROR",

            "message":
                str(ex)

        }), 500

def build_security_recommendations(device, correlation):
    """
    Build security recommendations from device posture,
    exposed services and traffic correlation.
    """

    recommendations = []

    risk_score = int(
        device.get("deviceRiskScore") or 0
    )

    risk_level = (
        device.get("deviceRiskLevel")
        or "Low"
    )

    open_ports = device.get("openPorts") or ""

    if isinstance(open_ports, str):
        open_ports = [
            str(port).strip()
            for port in open_ports.split(",")
            if str(port).strip()
        ]
    else:
        open_ports = [
            str(port).strip()
            for port in open_ports
            if str(port).strip()
        ]

    def add_recommendation(priority, title, detail):

        recommendations.append({
            "priority": priority,
            "title": title,
            "detail": detail
        })

    # -------------------------------------------------
    # Overall Risk
    # -------------------------------------------------

    if risk_score >= 80:

        add_recommendation(
            "Critical",
            "Prioritize immediate remediation",
            (
                f"The device has a {risk_score}/100 security risk score "
                f"({risk_level}). Review all identified security findings "
                "and exposed services before the device is considered trusted."
            )
        )

    elif risk_score >= 60:

        add_recommendation(
            "High",
            "Review high-risk security conditions",
            (
                f"The device has a {risk_score}/100 security risk score "
                f"({risk_level}). Review exposed services, detected controls "
                "and security findings."
            )
        )

    elif risk_score >= 40:

        add_recommendation(
            "Medium",
            "Improve device security posture",
            (
                f"The device has a {risk_score}/100 security risk score. "
                "Review the reported findings and reduce unnecessary exposure."
            )
        )

    # -------------------------------------------------
    # Open Ports
    # -------------------------------------------------

    if open_ports:

        port_list = ", ".join(open_ports[:10])

        add_recommendation(
            "Medium",
            "Review exposed network ports",
            (
                f"Review the following reported open port(s): {port_list}. "
                "Disable services that are not required and restrict access "
                "to management or administrative ports."
            )
        )

    # -------------------------------------------------
    # SSH
    # -------------------------------------------------

    if device.get("sshBannerDetected"):

        add_recommendation(
            "High",
            "Harden SSH access",
            (
                "SSH is detected on the device. Restrict SSH access to "
                "authorized management hosts, prefer key-based authentication "
                "and disable unnecessary administrative access."
            )
        )

    # -------------------------------------------------
    # HTTP / HTTPS
    # -------------------------------------------------

    if device.get("httpBannerDetected"):

        http_scheme = (
            device.get("httpScheme") or ""
        ).upper()

        if http_scheme == "HTTP":

            add_recommendation(
                "High",
                "Prefer HTTPS for web access",
                (
                    "HTTP access was detected. Use HTTPS wherever supported "
                    "to protect management traffic and credentials."
                )
            )

        else:

            add_recommendation(
                "Medium",
                "Review web management exposure",
                (
                    "A web service was detected. Restrict management access "
                    "to trusted hosts and verify that secure authentication "
                    "and HTTPS are enforced."
                )
            )

    # -------------------------------------------------
    # SNMP
    # -------------------------------------------------

    if device.get("snmpEnabled"):

        add_recommendation(
            "Medium",
            "Harden SNMP configuration",
            (
                "SNMP is enabled/detected. Restrict SNMP access to authorized "
                "management systems and prefer SNMPv3 with authentication "
                "and encryption where supported."
            )
        )

    # -------------------------------------------------
    # Traffic Correlation
    # -------------------------------------------------

    suspicious_packets = int(
        correlation.get("suspiciousPacketCount") or 0
    )

    if suspicious_packets > 0:

        add_recommendation(
            "High",
            "Investigate suspicious traffic",
            (
                f"{suspicious_packets} suspicious packet(s) were associated "
                "with this device. Review the corresponding traffic and "
                "determine whether the activity is expected."
            )
        )

    external_packets = int(
        correlation.get("externalPacketCount") or 0
    )

    if external_packets > 0:

        add_recommendation(
            "High",
            "Review external communication",
            (
                f"{external_packets} packet(s) communicated with external "
                "addresses. Validate the remote destinations and restrict "
                "unnecessary outbound communication."
            )
        )

    # -------------------------------------------------
    # Correlation Findings
    # -------------------------------------------------

    findings = correlation.get("findings") or []

    for finding in findings:

        title = (
            finding.get("title")
            if isinstance(finding, dict)
            else str(finding)
        )

        detail = (
            finding.get("detail")
            if isinstance(finding, dict)
            else ""
        )

        severity = (
            finding.get("severity", "Medium")
            if isinstance(finding, dict)
            else "Medium"
        )

        add_recommendation(
            severity,
            "Review correlated security finding",
            f"{title}. {detail}".strip()
        )

    # -------------------------------------------------
    # Remove duplicate recommendations
    # -------------------------------------------------

    unique = []
    seen = set()

    for recommendation in recommendations:

        key = (
            recommendation["title"],
            recommendation["detail"]
        )

        if key not in seen:
            seen.add(key)
            unique.append(recommendation)

    recommendations = unique

    # -------------------------------------------------
    # Low-risk / clean device
    # -------------------------------------------------

    if not recommendations:

        add_recommendation(
            "Low",
            "Maintain current security posture",
            (
                "No significant additional security action was identified "
                "from the current device and traffic analysis. Continue "
                "periodic monitoring and security assessment."
            )
        )

    return recommendations

def build_security_report(device):
    """
    Build a complete security report for a discovered device.
    """

    correlation = build_device_security_correlation(device)

    recommendations = build_security_recommendations(
        device,
        correlation
    )

    report = {
        "status": "SUCCESS",

        "report": {
            "generatedAt": datetime.now().strftime(
                "%d-%b-%Y %I:%M:%S %p"
            ),

            "reportType": "Device Security Report",

            "device": {
                "endpointId": device.get("endpointId"),
                "hostname": device.get("hostname"),
                "ip": device.get("ip"),
                "mac": device.get("mac"),
                "manufacturer": device.get("manufacturer"),
                "model": device.get("model"),
                "operatingSystem": device.get("operatingSystem"),
                "connectionType": device.get("connectionType")
            },

            "securityPosture": {
                "deviceRiskScore": device.get(
                    "deviceRiskScore",
                    0
                ),

                "deviceRiskLevel": device.get(
                    "deviceRiskLevel",
                    "Low"
                ),

                "riskReasons": device.get(
                    "deviceRiskReasons",
                    []
                )
            },

            "exposure": {
                "openPorts": device.get(
                    "openPorts",
                    ""
                ),

                "portDetails": device.get(
                    "portDetails",
                    []
                ),

                "services": device.get(
                    "services",
                    ""
                )
            },

            "securityControls": {
                "httpHttps": {
                    "detected": bool(
                        device.get("httpBannerDetected")
                    ),

                    "scheme": device.get(
                        "httpScheme"
                    )
                },

                "ssh": {
                    "detected": bool(
                        device.get("sshBannerDetected")
                    )
                },

                "snmp": {
                    "detected": bool(
                        device.get("snmpEnabled")
                    )
                }
            },

            "trafficCorrelation": correlation,
            
            "recommendations": recommendations
        }
    }

    return report

def build_device_security_correlation(device):
    """
    Correlate discovered device security information
    with currently captured network traffic.
    """

    device_ip = str(
        device.get("ip") or ""
    ).strip()

    open_ports = device.get("openPorts") or ""

    if isinstance(open_ports, str):
        open_ports = [
            str(port).strip()
            for port in open_ports.split(",")
            if str(port).strip()
        ]
    else:
        open_ports = [
            str(port).strip()
            for port in open_ports
            if str(port).strip()
        ]

    open_port_set = set(open_ports)

    packets = get_packets() or []

    device_packets = []

    for packet in packets:

        source = str(
            packet.get("source") or ""
        ).strip()

        destination = str(
            packet.get("destination") or ""
        ).strip()

        if source == device_ip or destination == device_ip:
            device_packets.append(packet)

    protocol_counter = Counter()
    observed_ports = Counter()
    remote_hosts = Counter()

    suspicious_packets = 0
    external_packets = 0
    inbound_packets = 0
    outbound_packets = 0

    def is_external_address(address):

        try:
            ip_obj = ipaddress.ip_address(address)

            return not (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
            )

        except Exception:
            return False

    for packet in device_packets:

        source = str(
            packet.get("source") or ""
        ).strip()

        destination = str(
            packet.get("destination") or ""
        ).strip()

        protocol = str(
            packet.get("protocol") or
            packet.get("transport") or
            "UNKNOWN"
        ).upper()

        protocol_counter[protocol] += 1

        if destination == device_ip:
            inbound_packets += 1

            source_port = str(
                packet.get("sourcePort") or ""
            ).strip()

            if source_port:
                observed_ports[source_port] += 1

            if source:
                remote_hosts[source] += 1

        elif source == device_ip:
            outbound_packets += 1

            destination_port = str(
                packet.get("destinationPort") or ""
            ).strip()

            if destination_port:
                observed_ports[destination_port] += 1

            if destination:
                remote_hosts[destination] += 1

        risk_score = int(
            packet.get("riskScore") or 0
        )

        if risk_score >= 60:
            suspicious_packets += 1

        remote_address = (
            destination
            if source == device_ip
            else source
        )

        if is_external_address(remote_address):
            external_packets += 1

    correlation_findings = []

    # -------------------------------------------------
    # Open Port <-> Observed Traffic Correlation
    # -------------------------------------------------

    for port in sorted(open_port_set, key=lambda value: int(value) if value.isdigit() else 99999):

        observed_count = observed_ports.get(port, 0)

        if observed_count > 0:

            correlation_findings.append({
                "severity": "Medium",
                "title": f"Open port {port} is actively used",
                "detail": (
                    f"Port {port} is reported as open and "
                    f"was observed in {observed_count} captured packet(s)."
                )
            })

    # -------------------------------------------------
    # SSH Correlation
    # -------------------------------------------------

    if device.get("sshBannerDetected"):

        ssh_count = observed_ports.get("22", 0)

        if ssh_count > 0:

            correlation_findings.append({
                "severity": "High",
                "title": "SSH service actively used",
                "detail": (
                    f"SSH was detected and traffic involving "
                    f"port 22 was observed {ssh_count} time(s)."
                )
            })

    # -------------------------------------------------
    # HTTP / HTTPS Correlation
    # -------------------------------------------------

    if device.get("httpBannerDetected"):

        web_ports = (
            observed_ports.get("80", 0)
            + observed_ports.get("443", 0)
            + observed_ports.get("8080", 0)
            + observed_ports.get("8443", 0)
        )

        if web_ports > 0:

            correlation_findings.append({
                "severity": "Medium",
                "title": "Web service actively used",
                "detail": (
                    f"HTTP/HTTPS was detected on the device and "
                    f"{web_ports} related packet(s) were observed."
                )
            })

    # -------------------------------------------------
    # SNMP Correlation
    # -------------------------------------------------

    if device.get("snmpEnabled"):

        snmp_count = observed_ports.get("161", 0)

        if snmp_count > 0:

            correlation_findings.append({
                "severity": "Medium",
                "title": "SNMP traffic detected",
                "detail": (
                    f"SNMP is enabled and UDP/161 traffic "
                    f"was observed {snmp_count} time(s)."
                )
            })

    # -------------------------------------------------
    # External Communication
    # -------------------------------------------------

    if external_packets > 0:

        correlation_findings.append({
            "severity": "High",
            "title": "External communication detected",
            "detail": (
                f"{external_packets} packet(s) involving this device "
                f"communicated with an external address."
            )
        })

    # -------------------------------------------------
    # Suspicious Packet Correlation
    # -------------------------------------------------

    if suspicious_packets > 0:

        correlation_findings.append({
            "severity": "High",
            "title": "Suspicious packet activity detected",
            "detail": (
                f"{suspicious_packets} packet(s) associated with this "
                f"device have a packet risk score of 60 or higher."
            )
        })

    # -------------------------------------------------
    # Correlation Risk Score
    # -------------------------------------------------

    base_score = int(
        device.get("deviceRiskScore") or 0
    )

    packet_scores = [
        int(packet.get("riskScore") or 0)
        for packet in device_packets
        if packet.get("riskScore") is not None
    ]

    average_packet_risk = (
        round(sum(packet_scores) / len(packet_scores), 2)
        if packet_scores
        else 0
    )

    if packet_scores:

        correlation_score = round(
            (base_score * 0.60)
            + (average_packet_risk * 0.40)
        )

    else:

        correlation_score = base_score

    correlation_score = max(
        0,
        min(correlation_score, 100)
    )

    if correlation_score >= 80:
        correlation_level = "Critical"

    elif correlation_score >= 60:
        correlation_level = "High"

    elif correlation_score >= 40:
        correlation_level = "Medium"

    else:
        correlation_level = "Low"

    return {
        "status": "SUCCESS",
        "endpointId": device.get("endpointId"),
        "ip": device_ip,

        "baseRiskScore": base_score,
        "baseRiskLevel": device.get(
            "deviceRiskLevel",
            "Low"
        ),

        "correlationRiskScore": correlation_score,
        "correlationRiskLevel": correlation_level,

        "packetCount": len(device_packets),
        "suspiciousPacketCount": suspicious_packets,
        "externalPacketCount": external_packets,

        "inboundPacketCount": inbound_packets,
        "outboundPacketCount": outbound_packets,

        "averagePacketRisk": average_packet_risk,

        "protocols": [
            {
                "name": name,
                "count": count
            }
            for name, count
            in protocol_counter.most_common()
        ],

        "observedPorts": [
            {
                "port": port,
                "count": count,
                "isOpen": port in open_port_set
            }
            for port, count
            in observed_ports.most_common()
        ],

        "topRemoteHosts": [
            {
                "host": host,
                "count": count
            }
            for host, count
            in remote_hosts.most_common(10)
        ],

        "findings": correlation_findings
    }

@app.route("/device-security-correlation", methods=["POST"])
def device_security_correlation():

    try:

        device = request.get_json(
            silent=True
        ) or {}

        endpoint_id = device.get(
            "endpointId"
        )

        ip = device.get("ip")

        target_device = None

        with device_lock:

            for item in latest_devices:

                if (
                    endpoint_id
                    and item.get("endpointId") == endpoint_id
                ):
                    target_device = item
                    break

                if (
                    not target_device
                    and ip
                    and item.get("ip") == ip
                ):
                    target_device = item

        if not target_device:

            return jsonify({
                "status": "ERROR",
                "message": "Device not found."
            }), 404

        result = build_device_security_correlation(
            target_device
        )

        return jsonify(result)

    except Exception as ex:

        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(ex)
        }), 500

@app.route("/security-report", methods=["POST"])
def security_report():

    try:

        device = request.get_json(
            silent=True
        ) or {}

        endpoint_id = device.get(
            "endpointId"
        )

        ip = device.get("ip")

        target_device = None

        with device_lock:

            for item in latest_devices:

                if (
                    endpoint_id
                    and item.get("endpointId") == endpoint_id
                ):
                    target_device = item
                    break

                if (
                    not target_device
                    and ip
                    and item.get("ip") == ip
                ):
                    target_device = item

        if not target_device:

            return jsonify({
                "status": "ERROR",
                "message": "Device not found."
            }), 404

        report = build_security_report(
            target_device
        )

        return jsonify(report)

    except Exception as ex:

        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(ex)
        }), 500

def background_scan():

    global latest_devices
    global last_scan_time
    global last_scan_duration

    # Wait before first background scan
    time.sleep(SCAN_INTERVAL)

    while True:

        try:
            start = time.time()
            with device_lock:
                latest_devices, last_scan_time, last_scan_duration = perform_network_scan()
                global latest_dashboard

                latest_dashboard = build_dashboard_summary(
                    latest_devices
                )

        except Exception as e:
            print(f"[{datetime.now()}] Scan failed: {e}")
            traceback.print_exc()

        elapsed = time.time() - start
        time.sleep(max(1, SCAN_INTERVAL - elapsed))

@app.route("/topology", methods=["GET"])
def get_topology():
    topology = build_network_topology(latest_devices)
    return jsonify(topology)
    #return jsonify(build_network_topology(latest_devices))

@app.route("/statistics")
def statistics():

    with device_lock:

        online = sum(
            1
            for d in latest_devices
            if d.get("active")
        )

        offline = len(latest_devices) - online

        manufacturer_stats = {}
        os_stats = {}
        discovery_stats = {}
        port_stats = {}
        service_stats = {}
        performance_stats = {}
        protocol_stats = {}
        risk_stats = {}
        category_stats = {}
        device_type_stats = {}
        topology_role_stats = {}

        for device in latest_devices:

            manufacturer = (
                device.get("manufacturer")
                or "Unknown"
            ).strip()

            manufacturer_stats[manufacturer] = (
                manufacturer_stats.get(manufacturer, 0) + 1
            )

            operating_system = (
                device.get("operatingSystem")
                or "Unknown"
            ).strip()

            os_stats[operating_system] = (
                os_stats.get(operating_system, 0) + 1
            )

            # Risk Level Statistics
            risk = (
                device.get("deviceRiskLevel")
                or "Unknown"
            ).strip()

            risk_stats[risk] = (
                risk_stats.get(risk, 0) + 1
            )

            # Category Statistics
            category = (
                device.get("category")
                or "Unknown"
            ).strip()

            category_stats[category] = (
                category_stats.get(category, 0) + 1
            )

            # Device Type Statistics
            device_type = (
                device.get("deviceType")
                or "Unknown"
            ).strip()

            device_type_stats[device_type] = (
                device_type_stats.get(device_type, 0) + 1
            )

            # Topology Role Statistics
            role = (
                device.get("topologyRole")
                or "Unknown"
            ).strip()

            topology_role_stats[role] = (
                topology_role_stats.get(role, 0) + 1
            )

            # Discovery Statistics
            discovery_sources = (
                device.get("discoverySource") or ""
            )

            for source in discovery_sources.split(","):
                source = source.strip()

                if source:
                    discovery_stats[source] = (discovery_stats.get(source, 0) + 1)
        
            # Port Statistics
            ports = device.get("openPorts")

            if ports:

                if isinstance(ports, str):
                    ports = ports.split(",")

                for port in ports:
                    port = str(port).strip()

                    if port:
                        port_stats[port] = (port_stats.get(port, 0) + 1)

            # Service Statistics
            services = device.get("services")

            if services:

                if isinstance(services, str):
                    services = services.split(",")

                for service in services:
                    service = service.strip()

                    if service:
                        service_stats[service] = (service_stats.get(service, 0) + 1)


            # Performance Statistics
            response = device.get("responseTime")

            if response:

                try:
                    response = float(
                        str(response).replace("ms", "")
                    )

                    if response < 10:
                        bucket = "< 10 ms"

                    elif response < 25:
                        bucket = "10 - 25 ms"

                    elif response < 50:
                        bucket = "25 - 50 ms"

                    elif response < 100:
                        bucket = "50 - 100 ms"

                    else:
                        bucket = "> 100 ms"

                    performance_stats[bucket] = (performance_stats.get(bucket, 0) + 1)

                except:

                    pass

            # Protocol Statistics
            protocols = set()

            primary_protocol = (device.get("primaryDiscoveryProtocol") or "").strip()
            last_protocol = (device.get("lastDiscoveryProtocol") or "").strip()

            if primary_protocol:
                protocols.add(primary_protocol)

            if last_protocol:
                protocols.add(last_protocol)

            for protocol in protocols:

                protocol_stats[protocol] = (protocol_stats.get(protocol, 0) + 1)

        manufacturers = []

        for name, count in sorted(
            manufacturer_stats.items(),
            key=lambda item: item[1],
            reverse=True
        ):

            manufacturers.append({
                "name": name,
                "count": count
            })

        operating_systems = []
        discoveries = []

        for name, count in sorted(

                discovery_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            discoveries.append({
                "name": name,
                "count": count
            })

        for name, count in sorted(
            os_stats.items(),
            key=lambda item: item[1],
            reverse=True
        ):

            operating_systems.append({
                "name": name,
                "count": count
            })

        ports = []

        for name, count in sorted(
                port_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            ports.append({
                "name": name,
                "count": count
            })

        services = []

        for name, count in sorted(
                service_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            services.append({
                "name": name,
                "count": count
            })

        performance = []

        order = [
            "< 10 ms",
            "10 - 25 ms",
            "25 - 50 ms",
            "50 - 100 ms",
            "> 100 ms"
        ]

        for bucket in order:

            performance.append({
                "name": bucket,
                "count": performance_stats.get(bucket, 0)
            })

        protocols = []

        for name, count in sorted(
                protocol_stats.items(),
                key=lambda item: item[1],
                reverse=True):

            protocols.append({
                "name": name,
                "count": count
            })

        riskLevels = []
        categories = []
        deviceTypes = []
        topologyRoles = []

        for name, count in sorted(
                risk_stats.items(),
                key=lambda item: item[1],
                reverse=True):
            riskLevels.append({
                "name": name,
                "count": count
            })

        for name, count in sorted(
                category_stats.items(),
                key=lambda item: item[1],
                reverse=True):
            categories.append({
                "name": name,
                "count": count
            })

        for name, count in sorted(
                device_type_stats.items(),
                key=lambda item: item[1],
                reverse=True):
            deviceTypes.append({
                "name": name,
                "count": count
            })

        for name, count in sorted(
                topology_role_stats.items(),
                key=lambda item: item[1],
                reverse=True):
            topologyRoles.append({
                "name": name,
                "count": count
            })

        return jsonify({
            "status": "SUCCESS",
            "total": len(latest_devices),
            "online": online,
            "offline": offline,
            "lastScan": last_scan_time,
            "scanDuration": last_scan_duration,
            "manufacturers": manufacturers,
            "operatingSystems": operating_systems,
            "discoveries": discoveries,
            "ports": ports,
            "services": services,
            "performance": performance,
            "protocols": protocols,
            "riskLevels": riskLevels,
            "categories": categories,
            "deviceTypes": deviceTypes,
            "topologyRoles": topologyRoles
        })

@app.route("/device/<ip>")
def device(ip):

    with device_lock:

        for d in latest_devices:

            if d.get("ip") == ip:
                return jsonify({
                    "status":"SUCCESS",
                    "device":d
                })

    return jsonify({
        "status":"ERROR",
        "message":"Device not found"
    }),404

@app.route("/ping")
def ping():

    return jsonify({
        "status":"UP",
        "time":datetime.now().strftime("%d-%b-%Y %I:%M:%S %p"),
        "version": API_VERSION
    })

@app.route("/version")
def version():

    return jsonify({
        "status": "SUCCESS",
        "version": API_VERSION,
        "build": BUILD_VERSION,
        "python": platform.python_version()
    })

@app.route("/traffic-analysis", methods=["GET"])
def traffic_analysis():

    try:
        requested_ip = request.args.get("ip", "").strip()

        if not os.path.exists(TRAFFIC_ANALYSIS_CACHE):
            return jsonify({
                "status": "ERROR",
                "message": "Traffic Analysis cache not available."
            }), 404

        with open(
            TRAFFIC_ANALYSIS_CACHE,
            "r",
            encoding="utf-8"
        ) as fp:

            result = json.load(fp)

        device_lookup = {
            device["ip"]: device
            for device in latest_devices
        }
        """
        device_lookup = {
            device.get("ip"): device
            for device in latest_devices
        }
        """

        for talker in result.get("topTalkers", []):

            device = device_lookup.get(talker.get("ip"))

            if device:

                talker["hostname"] = (
                    device.get("hostname")
                    or device.get("deviceName")
                    or device.get("friendlyName")
                    or "-"
                )

            else:

                talker["hostname"] = "Public Internet Host"

        for receiver in result.get("topReceivers", []):

            device = device_lookup.get(receiver.get("ip"))

            if device:

                receiver["hostname"] = (
                    device.get("hostname")
                    or device.get("deviceName")
                    or device.get("friendlyName")
                    or "-"
                )

            else:

                receiver["hostname"] = "Public Internet Host"

        """
        # Enrich Top Talkers
        for talker in result.get("topTalkers", []):

            hostname = get_hostname_from_ip(talker.get("ip"))

            if talker["ip"] in hostname_cache:

                hostname = hostname_cache[talker["ip"]]

            else:

                try:
                    hostname = socket.gethostbyaddr(
                        talker["ip"]
                    )[0]

                except:

                    hostname = "-"

                hostname_cache[talker["ip"]] = hostname
        """
        """
        # Enrich Top Receivers
        for receiver in result.get("topReceivers", []):

            hostname = get_hostname_from_ip(receiver.get("ip"))

            if hostname == "-":

                try:
                    hostname = socket.gethostbyaddr(
                        receiver["ip"]
                    )[0]
                except:
                    hostname = "-"

            receiver["hostname"] = hostname
        """

        if requested_ip:

            devices = result.get("devices", [])

            for device in devices:

                if device.get("ip") == requested_ip:

                    traffic_summary = {

                        **device,

                        "totalPackets": len(device.get("packets", [])),

                        "totalBytes": sum(
                            packet.get("length", 0)
                            for packet in device.get("packets", [])
                            if isinstance(packet.get("length", 0), (int, float))
                        ),

                        "connections": len(
                            {
                                (
                                    packet.get("source"),
                                    packet.get("destination")
                                )
                                for packet in device.get("packets", [])
                            }
                        )
                    }

                    traffic_summary["averagePacketSize"] = (
                        round(
                            traffic_summary["totalBytes"] /
                            traffic_summary["totalPackets"],
                            2
                        )
                        if traffic_summary["totalPackets"] > 0
                        else 0
                    )

                    traffic_summary["bandwidth"] = "-"

                    traffic_summary["captureDuration"] = "-"

                    protocol_stats = {}

                    for packet in device.get("packets", []):

                        protocol = (
                            packet.get("protocol") or
                            "Unknown"
                        ).upper()

                        protocol_stats[protocol] = (
                            protocol_stats.get(protocol, 0) + 1
                        )

                    traffic_summary["protocolStatistics"] = [

                        {
                            "protocol": protocol,
                            "packets": count
                        }

                        for protocol, count in sorted(
                            protocol_stats.items(),
                            key=lambda x: x[1],
                            reverse=True
                        )

                    ]

                    port_stats = {}

                    for packet in device.get("packets", []):

                        port = (
                            packet.get("destinationPort")
                            or packet.get("sourcePort")
                        )

                        if not port:
                            continue

                        port = str(port)

                        port_stats[port] = (
                            port_stats.get(port, 0) + 1
                        )

                    traffic_summary["topPorts"] = [

                        {
                            "port": port,
                            "packets": count
                        }

                        for port, count in sorted(
                            port_stats.items(),
                            key=lambda item: item[1],
                            reverse=True
                        )[:10]

                    ]

                    connection_stats = {}

                    for packet in device.get("packets", []):

                        source = packet.get("source")
                        destination = packet.get("destination")

                        if not source or not destination:
                            continue

                        key = (source, destination)

                        connection_stats[key] = (
                            connection_stats.get(key, 0) + 1
                        )

                    traffic_summary["topConnections"] = [

                        {
                            "source": source,
                            "destination": destination,
                            "packets": count
                        }

                        for (source, destination), count in sorted(
                            connection_stats.items(),
                            key=lambda item: item[1],
                            reverse=True
                        )[:10]

                    ]

                    talker_stats = {}

                    for packet in device.get("packets", []):

                        source = packet.get("source")

                        if not source:
                            continue

                        talker_stats[source] = (
                            talker_stats.get(source, 0) + 1
                        )

                    traffic_summary["topTalkers"] = [

                        {
                            "device": device_ip,
                            "packets": count
                        }

                        for device_ip, count in sorted(
                            talker_stats.items(),
                            key=lambda item: item[1],
                            reverse=True
                        )[:10]

                    ]

                    # Traffic Timeline
                    timeline = {}

                    for packet in device.get("packets", []):

                        packet_time = str(packet.get("time", "")).strip()

                        if not packet_time:
                            continue

                        # HH:MM:SS
                        bucket = packet_time.split(".")[0]

                        timeline[bucket] = timeline.get(bucket, 0) + 1

                    traffic_summary["trafficTimeline"] = [

                        {
                            "time": time_key,
                            "packets": count
                        }

                        for time_key, count in sorted(timeline.items())

                    ]

                    # AI Insights
                    most_active_protocol = (
                        traffic_summary["protocolStatistics"][0]["protocol"]
                        if traffic_summary["protocolStatistics"]
                        else "-"
                    )

                    top_port = (
                        traffic_summary["topPorts"][0]["port"]
                        if traffic_summary["topPorts"]
                        else "-"
                    )

                    top_talker = (
                        traffic_summary["topTalkers"][0]["device"]
                        if traffic_summary["topTalkers"]
                        else "-"
                    )

                    external_traffic = any(

                        not str(packet.get("destination", "")).startswith(("10.", "172.", "192.168."))

                        for packet in device.get("packets", [])

                    )

                    traffic_summary["aiInsights"] = {

                        "trafficHealth":
                            "Healthy"
                            if traffic_summary["totalPackets"] < 1000
                            else "Busy",

                        "mostActiveProtocol": most_active_protocol,

                        "topPort": top_port,

                        "topTalker": top_talker,

                        "externalCommunication":
                            "Detected"
                            if external_traffic
                            else "Internal Only",

                        "recommendation":
                            (
                                "Monitor external communications."
                                if external_traffic
                                else "Traffic appears normal."
                            )
                    }

                    return jsonify({

                        "status": "SUCCESS",

                        "device": traffic_summary

                    })

            return jsonify({
                "status": "ERROR",
                "message": "Device not found."
            }), 404

        return jsonify(result)

    except json.JSONDecodeError:
        return jsonify({
            "status": "ERROR",
            "message":
                "Traffic Analysis cache is being updated."
        }),503

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

@app.route("/risk-analysis", methods=["GET"])
def risk_analysis():

    try:
        if not os.path.exists(RISK_ANALYSIS_CACHE):
            return jsonify({
                "status":"ERROR",
                "message":"Risk Analysis cache not available."
            }),404

        with open(RISK_ANALYSIS_CACHE, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        return jsonify(data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(e)
        }),500

@app.route("/deep-analysis", methods=["POST"])
def deep_analysis():

    try:
        request_data = request.get_json(silent=True) or {}

        if not isinstance(request_data, dict):
            return jsonify({
                "status": "ERROR",
                "message": "Request body must be a JSON object."
            }), 400

        packet_number = request_data.get("packetNumber")

        if packet_number is None:
            return jsonify({
                "status": "ERROR",
                "message": "packetNumber is required."
            }), 400

        packets = get_packets()
        packet_window = get_packet_context(
            packets,
            packet_number
        )

        if not packet_window:
            return jsonify({
                "status": "ERROR",
                "message": "No packets available for Deep Analysis."
            }), 400

        _wait_for_ai_request_slot()
        analysis = analyze_packet_window(packet_window)
        #print("=" * 80)
        #print("Deep Analysis Response")
        #print(analysis)
        #print(type(analysis))
        #print("=" * 80)

        return jsonify({
            "status": "SUCCESS",
            "analysis": analysis
        })

    except LocalAIRateLimitError as ex:
        return _rate_limited_response(
            str(ex),
            ex.retry_after
        )

    except RateLimitError as ex:
        retry_after = _record_ai_provider_rate_limit(ex)

        return _rate_limited_response(
            "AI provider rate limit reached. Please try again later.",
            retry_after
        )
    
    except Exception as ex:
        import traceback
        traceback.print_exc()

        return jsonify({
            "status": "ERROR",
            "message": str(ex)
        }), 500

@app.route("/ai/analyze_packet", methods=["POST"])
def analyze_packet():

    try:
        packet = request.get_json(force=True)
        if not packet:
            return jsonify({
                "status": "ERROR",
                "message": "Packet data not received."
            }),400

          # Category Information
        category_result = {
            "category":
                packet.get("category","Unknown"),
            "baseRisk":
                _safe_int(
                    packet.get("riskScore"),
                    0
                )

        }

   
        # AI Risk Engine
        risk = risk_engine.calculate(
            packet,
            category_result
        )

        packet_explainability = build_packet_ai_explainability(
            packet,
            risk
        )

        # Update the Live Packet Buffer
        packets = get_packets()

        for live_packet in packets:

            if (
                live_packet.get("id") == packet.get("id")
                or
                live_packet.get("number") == packet.get("number")
            ):

                live_packet["riskScore"] = risk["riskScore"]
                live_packet["riskLevel"] = risk["riskLevel"]
                live_packet["confidence"] = risk["confidence"]
                live_packet["category"] = risk["category"]
                live_packet["suspicious"] = risk["suspicious"]

                break

        # AI Explanation
        explanation = []

        if risk["riskLevel"] == "Critical":
            explanation.append(
                "Critical risk packet detected."
            )
        elif risk["riskLevel"] == "High":
            explanation.append(
                "High risk packet detected."
            )
        elif risk["riskLevel"] == "Medium":
            explanation.append(
                "Medium risk packet detected."
            )
        else:
            explanation.append(
                "Low risk packet."
            )

        # External Destination
        destination = str(
            packet.get(
                "destination",
                ""
            )
        )

        if destination and not (
            destination.startswith("10.")
            or
            destination.startswith("172.")
            or
            destination.startswith("192.168.")
        ):

            explanation.append(
                "Traffic is leaving the private network."
            )


        # Large Packet
        if int(packet.get("length",0)) > 1400:
            explanation.append(
                "Large packet detected."
            )

        # Final Response
        return jsonify({
        "status": "SUCCESS",
        "packetNumber": packet.get("number"),
        "analysis": {
            **risk,
            "category": category_result["category"],
            "ai": " ".join(explanation),
            "protocol": packet.get("protocol"),
            "transport": packet.get("transport"),
            "length": packet.get("length"),
            "source": packet.get("source"),
            "destination": packet.get("destination"),
            "sourcePort": packet.get("sourcePort"),
            "destinationPort": packet.get("destinationPort"),
            "explainability": packet_explainability
        }
    })

    except Exception as ex:
        traceback.print_exc()
        return jsonify({
            "status":"ERROR",
            "message":str(ex)
        }),500

@app.route("/analyze_device", methods=["POST"])
def analyze_device():

    try:

        device = request.get_json(force=True)

        result, cache_hit = _analyze_device_cached(
            device
        )

        return jsonify({
            "status": "SUCCESS",
            **result,
            "cacheHit": cache_hit
        })
    

    except Exception as ex:

        traceback.print_exc()

        return jsonify({

            "status": "ERROR",

            "error": str(ex)

        }), 500

if __name__ == '__main__':
    """
    print("=" * 60)
    print("Network Monitoring API Started")
    print(f"Version              : {API_VERSION}")
    print(f"Host                 : {HOST}")
    print(f"Port                 : {PORT}")
    print(f"Scan Interval        : {SCAN_INTERVAL} sec")
    print(f"Packet Capture       : {ENABLE_PACKET_CAPTURE}")
    print(f"Background Scan      : {ENABLE_BACKGROUND_SCAN}")
    print("=" * 60)
    """
    # Clean all old traffic analysis files
    #if os.path.isdir(TRAFFIC_PCAPTRACE_FOLDER): shutil.rmtree(TRAFFIC_PCAPTRACE_FOLDER)
    #os.makedirs(TRAFFIC_PCAPTRACE_FOLDER, exist_ok=True)
    #if os.path.exists(TRAFFIC_ANALYSIS_CACHE): os.remove(TRAFFIC_ANALYSIS_CACHE)
    #if os.path.exists(TRAFFIC_ANALYSIS_HISTORY): os.remove(TRAFFIC_ANALYSIS_HISTORY)
    #if os.path.exists(RISK_ANALYSIS_CACHE): os.remove(RISK_ANALYSIS_CACHE)
    #if os.path.exists(RISK_ANALYSIS_HISTORY): os.remove(RISK_ANALYSIS_HISTORY)
    
    
    # Start packet capture
    if ENABLE_PACKET_CAPTURE:
        try:
            start_capture()

        except Exception as e:
            print(f"[{datetime.now()}] Packet Capture failed : {e}")
            traceback.print_exc()

    background_thread = None

    if ENABLE_BACKGROUND_SCAN:

        threading.Thread(
            target=background_scan,
            daemon=True,
            name="BackgroundScan"
        ).start()

    try:

        app.run(
            host=HOST,
            port=PORT,
            debug=False
        )

    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("Stopping Network Monitoring API...")
        print("=" * 60)

    except Exception as ex:

        print(f"Server Error : {ex}")
        traceback.print_exc()

    finally:
        time.sleep(1)
        print("Server shutdown completed.")