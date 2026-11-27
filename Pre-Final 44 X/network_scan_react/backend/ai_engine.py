import json
from groq import Groq
# from config import GROQ_API_KEY
from prompts import AI_SYSTEM_PROMPT
# from ai_feedback import get_learning_examples


GROQ_API_KEY = "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"


class AIEngine:

    def __init__(self):

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

Analyze the selected packet using the available packet
data, surrounding packet context, and historical human
feedback when relevant.

Historical human feedback is guidance only. The current
packet evidence must remain the primary basis for the
analysis.

Return JSON only.
"""


        # ---------------------------------------------------------
        # Groq AI Request
        # ---------------------------------------------------------

        try:

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

                temperature=0.8,

                max_tokens=1500,

                response_format={
                    "type": "json_object"
                }

            )

            return (
                response
                .choices[0]
                .message
                .content
            )


        # ---------------------------------------------------------
        # Error Handling
        # ---------------------------------------------------------

        except Exception as e:

            return json.dumps({

                "risk_score": 0,

                "risk_level": "UNKNOWN",

                "confidence": 0,

                "category": "Error",

                "summary": str(e),

                "reasoning": [],

                "observations": [],

                "patterns": [],

                "recommendations": []

            })


ai_engine = AIEngine()