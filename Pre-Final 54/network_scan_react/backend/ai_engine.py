import os
import json

from dotenv import load_dotenv
from groq import Groq, RateLimitError

from prompts import AI_SYSTEM_PROMPT


load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


class AIEngine:

    def __init__(self):
        self.client = Groq(
            api_key=GROQ_API_KEY,
            timeout=45.0,
            max_retries=0
        )

        self.model = "openai/gpt-oss-20b"
        # self.model = "llama-3.1-8b-instant"

    def ask(self, packet, context_packets):
        if not isinstance(context_packets, list):
            context_packets = []

        context_packets = context_packets[:4]

        
        prompt = f"""
Analyze the selected network packet for security relevance.

Analysis rules:
1. Treat the selected packet as the primary subject.
2. Use nearby packets only as supporting context.
3. Base every finding on supplied packet fields.
4. Separate observed facts from inferred possibilities.
5. Do not invent host identities, authentication outcomes,
   malware, attacks, or geographic locations.
6. Do not classify SSH or another administrative protocol
   as suspicious solely because the protocol is present.
7. Use risk_score from 0 to 100. Use 0 when no meaningful
   security concern is supported by the evidence.
8. Keep risk_level consistent with the evidence and risk_score.
9. Keep summary concise and reasoning evidence-based.
10. Provide actionable recommendations only when justified.
11. Return all required fields with the correct data types.
12. Return valid JSON only, with no Markdown.

Selected packet:
{json.dumps(packet, separators=(",", ":"), default=str)}

Nearby packets:
{json.dumps(context_packets, separators=(",", ":"), default=str)}
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
                temperature=0.2,
                max_completion_tokens=500,
                reasoning_effort="low",
                include_reasoning=False,
                response_format={
                    "type": "json_object"
                }
            )

            content = response.choices[0].message.content

            if not content:
                raise ValueError("AI returned an empty response.")

            analysis = json.loads(content)

            if not isinstance(analysis, dict):
                raise ValueError("AI returned an invalid JSON object.")

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

            unexpected_fields = set(analysis) - set(required_fields)
            if unexpected_fields:
                raise ValueError(
                    "AI response contains unexpected fields: "
                    + ", ".join(sorted(unexpected_fields))
                )

            if (
                not isinstance(analysis["risk_score"], int)
                or isinstance(analysis["risk_score"], bool)
                or not 0 <= analysis["risk_score"] <= 100
            ):
                raise ValueError("Invalid risk_score.")

            if (
                not isinstance(analysis["confidence"], int)
                or isinstance(analysis["confidence"], bool)
                or not 0 <= analysis["confidence"] <= 100
            ):
                raise ValueError("Invalid confidence.")
            
            allowed_risk_levels = {
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
                "UNKNOWN"
            }

            if (
                not isinstance(analysis["risk_level"], str)
                or analysis["risk_level"].upper()
                not in allowed_risk_levels
            ):
                raise ValueError("Invalid risk_level.")

            analysis["risk_level"] = analysis["risk_level"].upper()

            expected_risk_level = (
                "LOW" if analysis["risk_score"] <= 24 else
                "MEDIUM" if analysis["risk_score"] <= 49 else
                "HIGH" if analysis["risk_score"] <= 79 else
                "CRITICAL"
            )

            if (
                analysis["risk_level"] != "UNKNOWN"
                and analysis["risk_level"] != expected_risk_level
            ):
                raise ValueError(
                    "risk_level does not match risk_score."
                )

            if (
                not isinstance(analysis["category"], str)
                or not analysis["category"].strip()
            ):
                raise ValueError("Invalid category.")
            
            for field in ("summary", "reasoning"):
                if (
                    not isinstance(analysis[field], str)
                    or not analysis[field].strip()
                ):
                    raise ValueError(f"Invalid {field}.")

            for field in (
                "observations",
                "patterns",
                "recommendations"
            ):
                if not isinstance(analysis[field], list):
                    raise ValueError(f"Invalid {field}.")

            for field in (
                "observations",
                "patterns",
                "recommendations"
            ):
                if not all(
                    isinstance(item, str) and item.strip()
                    for item in analysis[field]
                ):
                    raise ValueError(
                        f"Invalid item in {field}."
                    )

            return json.dumps(analysis)

        except RateLimitError:
            # Let the caller/server handle HTTP 429 without disguising it
            # as a successful-looking AI response.
            raise

        except Exception:
            raise


ai_engine = AIEngine()
