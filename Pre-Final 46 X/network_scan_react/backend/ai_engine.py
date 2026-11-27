import os
import json
import logging
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# from config import GROQ_API_KEY
from prompts import AI_SYSTEM_PROMPT

# from ai_feedback import get_learning_examples
from ai_rules import get_ai_config

logger = logging.getLogger(__name__)

# Load the Groq API key from an environment variable.
# Set GROQ_API_KEY before starting the application.
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Groq TPM protection / prompt-size controls.
# Keep these values conservative for the current 8K TPM organization limit.
MAX_FEEDBACK_EXAMPLES = 2
MAX_PACKET_CONTEXT = 4
MAX_OUTPUT_TOKENS = 350

# GPT-OSS is a reasoning model. Keep reasoning deliberately low and
# exclude the reasoning trace from the response so JSON mode receives
# only the application result.
REASONING_EFFORT = "low"
INCLUDE_REASONING = False

def _compact_feedback_examples(feedback_examples):
    """
    Keep only the fields that are useful for learning from historical
    feedback. This prevents large historical records from consuming
    Groq TPM/TPD budget.
    """

    if not isinstance(feedback_examples, list):
        return []

    compact = []

    # Common fields used by packet/device feedback records.
    allowed_fields = {
        "analysisType",
        "packetId",
        "packetNumber",
        "deviceId",
        "endpointId",
        "ip",
        "mac",
        "hostname",
        "predictedRisk",
        "predictedScore",
        "predictedCategory",
        "correctedRisk",
        "correctedCategory",
        "feedback",
        "comment",
        "riskScore",
        "riskLevel",
        "category",
        "suspicious",
        "confidence",
        "summary",
        "reasoning",
        "recommendations"
    }

    # Keep strings bounded as an additional prompt-size safeguard.
    max_string_length = 300

    for item in feedback_examples[-MAX_FEEDBACK_EXAMPLES:]:
        if not isinstance(item, dict):
            continue

        compact_item = {}

        for key in allowed_fields:
            if key not in item:
                continue

            value = item.get(key)

            if isinstance(value, str):
                compact_item[key] = value[:max_string_length]
            elif isinstance(value, list):
                compact_item[key] = value[:5]
            elif isinstance(value, dict):
                compact_item[key] = value
            else:
                compact_item[key] = value

        if compact_item:
            compact.append(compact_item)

    return compact


class AIEngine:

    def __init__(self):

        if not GROQ_API_KEY:

            raise RuntimeError(
                "GROQ_API_KEY environment variable is not set."
            )

        self.client = Groq(
            api_key=GROQ_API_KEY
        )

        # self.model = "llama-3.1-8b-instant"
        self.model = "openai/gpt-oss-20b"

    def ask(
        self,
        packet,
        context_packets,
        feedback_examples=None
    ):

        # ---------------------------------------------------------
        # Historical Human Feedback
        # ---------------------------------------------------------

        feedback_context = ""

        if feedback_examples:

            try:

                # Limit historical feedback so it does not consume
                # most of the Groq TPM budget.
                compact_feedback = _compact_feedback_examples(feedback_examples)

                feedback_context = f"""

Historical Human Feedback

The following feedback was provided by human reviewers
for previous AI assessments.

Use this information only as supporting evidence when
analyzing the current packet.

Do NOT blindly copy previous decisions.

Previous feedback:

{json.dumps(
    compact_feedback,
    separators=(",", ":")
)}

"""

            except Exception:

                feedback_context = ""


        # ---------------------------------------------------------
        # Custom AI Configuration / Tuning
        # ---------------------------------------------------------

        ai_config = get_ai_config()

        custom_instructions = (
            ai_config.get(
                "custom_instructions",
                ""
            )
            if ai_config.get(
                "enabled",
                True
            )
            else ""
        )

        custom_instruction_context = ""

        if custom_instructions:

            custom_instruction_context = f"""

Custom Network Monitoring Instructions

Apply the following administrator-defined
instructions when relevant:

{custom_instructions}

These instructions must not override
actual packet evidence.

"""


        # ---------------------------------------------------------
        # Build AI Prompt
        # ---------------------------------------------------------

        prompt = f"""

Selected Packet

{json.dumps(
    packet,
    separators=(",", ":")
)}

Nearby Packets

{json.dumps(
    context_packets[-MAX_PACKET_CONTEXT:]
        if isinstance(context_packets, list)
        else context_packets,
    separators=(",", ":")
)}

{feedback_context}

{custom_instruction_context}

Analyze the selected packet using the available packet
data, surrounding packet context, and historical human
feedback when relevant.

Historical human feedback is guidance only. The current
packet evidence must remain the primary basis for the
analysis.

Custom administrator instructions are additional guidance
only and must not override actual packet evidence.

Return JSON only.
"""


        # ---------------------------------------------------------
        # Groq AI Request
        # ---------------------------------------------------------

        try:

            if ai_config.get(
                "enabled",
                True
            ):
                temperature = float(
                    ai_config.get(
                        "temperature",
                        0.3
                    )
                )
            else:
                temperature = 0.3

            temperature = max(
                0.0,
                min(
                    1.0,
                    temperature
                )
            )

            response = self.client.chat.completions.create(

                model=self.model,

                messages=[

                    {
                        "role": "system",
                        "content": AI_SYSTEM_PROMPT
                    },

                    {
                        "role": "user",
                        "content": prompt
                    }

                ],

                temperature=temperature,

                # max_completion_tokens is the current Groq parameter.
                # 350 is enough for the compact AI result while keeping
                # token usage low for the current organization TPM limit.
                max_completion_tokens=MAX_OUTPUT_TOKENS,

                # GPT-OSS performs internal reasoning. Do not include the
                # reasoning trace in the response and keep reasoning low;
                # otherwise JSON mode can fail validation.
                reasoning_effort=REASONING_EFFORT,
                include_reasoning=INCLUDE_REASONING,

                response_format={
                    "type": "json_object"
                }
            )

            content = (
                response
                .choices[0]
                .message
                .content
            )

            analysis = json.loads(content)

            if not isinstance(analysis, dict):
                raise ValueError(
                    "AI response must be a JSON object."
                )

            if "riskScore" not in analysis:
                analysis["riskScore"] = analysis.get(
                    "risk_score",
                    0
                )

            if "riskLevel" not in analysis:
                analysis["riskLevel"] = analysis.get(
                    "risk_level",
                    "UNKNOWN"
                )

            if "confidence" not in analysis:
                analysis["confidence"] = 0

            if "category" not in analysis:
                analysis["category"] = "Unknown"

            if "suspicious" not in analysis:
                analysis["suspicious"] = False

            return json.dumps(analysis)


        # ---------------------------------------------------------
        # Error Handling
        # ---------------------------------------------------------

        except Exception as e:

            logger.exception(
                "AI analysis failed."
            )

            raise RuntimeError(
                f"AI analysis failed: {e}"
            ) from e

    def ask_device(
        self,
        device,
        baseline_analysis,
        feedback_examples=None
    ):

        ai_config = get_ai_config()

        custom_instructions = (
            ai_config.get(
                "custom_instructions",
                ""
            )
            if ai_config.get(
                "enabled",
                True
            )
            else ""
        )

        custom_instruction_context = ""

        if custom_instructions:

            custom_instruction_context = f"""

Custom Network Monitoring Instructions

{custom_instructions}

These instructions must not override
actual device evidence.

"""

        # ---------------------------------------------------------
        # Compact Device AI Context
        # ---------------------------------------------------------

        device_context = {
            "ip": device.get("ip"),
            "mac": device.get("mac"),
            "hostname": device.get("hostname"),
            "manufacturer": device.get("manufacturer"),
            "model": device.get("model"),
            "operatingSystem": device.get("operatingSystem"),
            "deviceType": device.get("deviceType"),
            "category": device.get("category"),
            "connectionType": device.get("connectionType"),
            "discoverySource": device.get("discoverySource"),
            "openPorts": device.get("openPorts"),
            "services": device.get("services"),
            "httpScheme": device.get("httpScheme"),
            "httpBannerDetected": device.get("httpBannerDetected"),
            "snmpEnabled": device.get("snmpEnabled"),
            "sshBannerDetected": device.get("sshBannerDetected"),
            "deviceRiskScore": device.get("deviceRiskScore"),
            "deviceRiskLevel": device.get("deviceRiskLevel"),
            "deviceRiskReasons": device.get("deviceRiskReasons")
        }

        baseline_context = {
            "summary": baseline_analysis.get("ai"),
            "executiveSummary": baseline_analysis.get("executiveSummary"),
            "deviceType": baseline_analysis.get("deviceType"),
            "fingerprint": baseline_analysis.get("fingerprint"),
            "networkRole": baseline_analysis.get("networkRole"),
            "riskScore": baseline_analysis.get("riskScore"),
            "riskLevel": baseline_analysis.get("riskLevel"),
            "securityGrade": baseline_analysis.get("securityGrade"),
            "attackSurface": baseline_analysis.get("attackSurface"),
            "riskIndicators": baseline_analysis.get("riskIndicators"),
            "securityPosture": baseline_analysis.get("securityPosture"),
            "reasons": baseline_analysis.get("reasons"),
            "recommendations": baseline_analysis.get("recommendations")
        }

        feedback_context = ""

        if feedback_examples:

            # Keep only the most recent few examples. This prevents
            # historical feedback from consuming the Groq TPM budget.
            compact_feedback = _compact_feedback_examples(feedback_examples)

            feedback_context = f"""

Historical Human Feedback

{json.dumps(
    compact_feedback,
    separators=(",", ":")
)}

"""

        prompt = f"""

Selected Device Evidence

{json.dumps(
    device_context,
    separators=(",", ":")
)}

Baseline Security Analysis

{json.dumps(
    baseline_context,
    separators=(",", ":")
)}

{feedback_context}

{custom_instruction_context}

Analyze the device using the current
device evidence as the primary source.

Use the baseline analysis as supporting
evidence only.

Historical feedback is guidance only.

Custom administrator instructions are
additional guidance only.

Return JSON only.

Required fields:

riskScore
riskLevel
confidence
category
suspicious
summary
reasoning
recommendations
"""

        try:

            if ai_config.get(
                "enabled",
                True
            ):
                temperature = float(
                    ai_config.get(
                        "temperature",
                        0.3
                    )
                )
            else:
                temperature = 0.3

            temperature = max(
                0.0,
                min(
                    1.0,
                    temperature
                )
            )

            response = self.client.chat.completions.create(

                model=self.model,

                messages=[

                    {
                        "role": "system",
                        "content": AI_SYSTEM_PROMPT
                    },

                    {
                        "role": "user",
                        "content": prompt
                    }

                ],

                temperature=temperature,

                # max_completion_tokens is the current Groq parameter.
                # 350 is enough for the compact AI result while keeping
                # token usage low for the current organization TPM limit.
                max_completion_tokens=MAX_OUTPUT_TOKENS,

                # GPT-OSS performs internal reasoning. Do not include the
                # reasoning trace in the response and keep reasoning low;
                # otherwise JSON mode can fail validation.
                reasoning_effort=REASONING_EFFORT,
                include_reasoning=INCLUDE_REASONING,

                response_format={
                    "type": "json_object"
                }
            )

            content = (
                response
                .choices[0]
                .message
                .content
            )

            analysis = json.loads(
                content
            )

            if not isinstance(analysis, dict):
                raise ValueError(
                    "Device AI response must be a JSON object."
                )

            if "riskScore" not in analysis:
                analysis["riskScore"] = analysis.get(
                    "risk_score",
                    0
                )

            if "riskLevel" not in analysis:
                analysis["riskLevel"] = analysis.get(
                    "risk_level",
                    "UNKNOWN"
                )

            if "confidence" not in analysis:
                analysis["confidence"] = 0

            if "category" not in analysis:
                analysis["category"] = "Unknown"

            if "suspicious" not in analysis:
                analysis["suspicious"] = False

            return json.dumps(
                analysis
            )

        except Exception as e:

            logger.exception(
                "Device AI analysis failed."
            )

            raise RuntimeError(
                f"Device AI analysis failed: {e}"
            ) from e

ai_engine = AIEngine()