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


class AIEngine:

    def __init__(self):

        if not GROQ_API_KEY:

            raise RuntimeError(
                "GROQ_API_KEY environment variable is not set."
            )

        self.client = Groq(
            api_key=GROQ_API_KEY
        )

        self.model = "llama-3.1-8b-instant"

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

                feedback_context = f"""

Historical Human Feedback

The following feedback was provided by human reviewers
for previous AI assessments.

Use this information only as supporting evidence when
analyzing the current packet.

Do NOT blindly copy previous decisions.

Previous feedback:

{json.dumps(
    feedback_examples,
    indent=2
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
    indent=2
)}

Nearby Packets

{json.dumps(
    context_packets,
    indent=2
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

                max_tokens=1500,

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

        feedback_context = ""

        if feedback_examples:

            feedback_context = f"""

Historical Human Feedback

{json.dumps(
    feedback_examples,
    indent=2
)}

"""

        prompt = f"""

Selected Device

{json.dumps(
    device,
    indent=2
)}

Baseline Device Analysis

{json.dumps(
    baseline_analysis,
    indent=2
)}

{feedback_context}

{custom_instruction_context}

Analyze the device using the current
device evidence.

Historical feedback is guidance only.

Custom administrator instructions are
additional guidance only.

Return JSON only.
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

                max_tokens=1500,

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