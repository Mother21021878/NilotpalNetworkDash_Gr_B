import os
import json

from groq import Groq
from prompts import AI_SYSTEM_PROMPT
from dotenv import load_dotenv


load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
#GROQ_API_KEY = "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"


class AIEngine:

    def __init__(self):

        self.client = Groq(
            api_key=GROQ_API_KEY
        )

        self.model = "openai/gpt-oss-20b"
        #self.model = "llama-3.1-8b-instant"


    def ask(self, packet, context_packets):

        prompt = f"""
Analyze the selected network packet using the supplied packet context.

IMPORTANT:

- The selected packet is the primary subject of the analysis.
- Nearby packets provide supporting context.
- Use only the information contained in the supplied data.
- Do not invent authentication results, usernames, malware, attack tools,
  host identities, geographic locations or other unsupported facts.
- Distinguish observed facts from inferred or possible conditions.
- Evaluate the selected packet together with the surrounding traffic.
- Determine the security attention level using the evidence-based rules
  defined in the system prompt.
- A risk_score of 0 is valid when the traffic appears normal and there is
  no meaningful security concern.
- Do not automatically classify administrative protocols such as SSH as
  HIGH risk without supporting evidence.
- Return exactly the JSON structure required by the system prompt.

Selected Packet
---------------

{json.dumps(packet, indent=2)}

Nearby Packets
--------------

{json.dumps(context_packets, indent=2)}

Analyze the selected packet now and return JSON only.
"""

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

                temperature=0.6,
                max_completion_tokens=1000,
                reasoning_effort="low",
                include_reasoning=False,
                response_format={
                    "type": "json_object"
                }

            )

            content = response.choices[0].message.content

            if not content:

                raise ValueError(
                    "AI returned an empty response."
                )

            analysis = json.loads(content)

            if not isinstance(analysis, dict):

                raise ValueError(
                    "AI returned an invalid JSON object."
                )

            required_fields = [

                "risk_score",
                "risk_level",
                "confidence",
                "category",
                "summary",
                "reasoning",
                "observations",
                "patterns",
                "recommendations"

            ]

            missing_fields = [

                field
                for field in required_fields
                if field not in analysis

            ]

            if missing_fields:

                raise ValueError(
                    "AI response is missing required fields: "
                    + ", ".join(missing_fields)
                )

            return json.dumps(analysis)

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