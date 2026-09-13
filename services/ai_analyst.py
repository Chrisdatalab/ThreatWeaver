import json
import os

from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)
def build_ai_prompt(context):
    context_json = json.dumps(
        context,
        indent=2
    )

    prompt = f"""
You are a security analyst reviewing ThreatWeaver results.

Rules:
- Use only the provided findings and correlations.
- A finding does not prove compromise.
- Only relationships in correlations are confirmed.
- Separate evidence from possible explanations.
- Do not combine unrelated hosts or time periods.

Provide:
- Summary
- Risk
- Key findings
- Confirmed correlations
- Investigation steps

{context_json}
"""

    return prompt
def analyze_security_context(context):
    prompt = build_ai_prompt(context)

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt
    )

    return response.output_text

def answer_security_question(context, question, history):
    context_json = json.dumps(
        context,
        indent=2
    )

    history_json = json.dumps(
        history,
        indent=2
    )

    prompt = f"""
You are a security analyst helping investigate ThreatWeaver results.

Rules:
- Answer using the provided security data.
- Do not invent findings or correlations.
- A finding does not prove compromise.
- Only relationships in correlations are confirmed.

Security data:

{context_json}

Conversation history:

{history_json}

User question:

{question}
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt
    )

    return response.output_text