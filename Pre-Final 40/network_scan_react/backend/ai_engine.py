import json
from groq import Groq
# from config import GROQ_API_KEY
from prompts import AI_SYSTEM_PROMPT


GROQ_API_KEY = "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"
class AIEngine:

    def __init__(self):

        self.client = Groq(
            api_key=GROQ_API_KEY
        )

        self.model = "llama-3.1-8b-instant"

    def ask(self, packet, context_packets):

        prompt = f"""
Selected Packet

{json.dumps(packet, indent=2)}

Nearby Packets

{json.dumps(context_packets, indent=2)}
"""

        try:

            response = self.client.chat.completions.create(

                model=self.model,

                messages=[

                    {
                        "role":"system",
                        "content":AI_SYSTEM_PROMPT
                    },

                    {
                        "role":"user",
                        "content":prompt
                    }

                ],

                temperature=0.8,
                max_tokens=1500,
                response_format={
                    "type":"json_object"
                }

            )

            return response.choices[0].message.content

        except Exception as e:

            return json.dumps({

                "risk_score":0,
                "risk_level":"UNKNOWN",
                "confidence":0,
                "category":"Error",
                "summary":str(e),
                "reasoning":[],
                "observations":[],
                "patterns":[],
                "recommendations":[]

            })


ai_engine = AIEngine()