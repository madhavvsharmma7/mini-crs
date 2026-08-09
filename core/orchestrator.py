import os
import json
import re
from pathlib import Path
from groq import Groq

# Load .env from project root regardless of where script is run from
env_path = Path(__file__).resolve().parent.parent / '.env'
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, val = line.split('=', 1)
                os.environ.setdefault(key.strip(), val.strip())

client = Groq(api_key=os.environ["GROQ_API_KEY"])

def clean_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        text = text.rsplit("```", 1)[0]
    text = text.strip()
    # Remove control characters except newlines/tabs
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text

def run_agent(system_prompt: str, user_message: str) -> str:
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        temperature=0.1
    )
    return clean_json(response.choices[0].message.content)


AGENT_1_SYSTEM = """You are a static code analyzer for a Cyber Reasoning System.
Analyze the given code and identify ALL security vulnerabilities.

Respond ONLY in this JSON format (no markdown, no preamble, no extra text):
{
  "vulnerabilities": [
    {
      "line": null,
      "type": "vulnerability type",
      "description": "what is wrong",
      "severity": "CRITICAL"
    }
  ],
  "summary": "one line summary"
}"""

AGENT_2_SYSTEM = """You are a CWE/CVE classification expert in a Cyber Reasoning System.
Classify each vulnerability from the input.

Respond ONLY in this JSON format (no markdown, no preamble, no extra text):
{
  "classifications": [
    {
      "type": "vulnerability type from input",
      "cwe_id": "CWE-89",
      "cwe_name": "official CWE name",
      "cvss_score": 9.8,
      "attack_vector": "how this can be exploited"
    }
  ]
}"""

AGENT_3_SYSTEM = """You are a secure code patch generator in a Cyber Reasoning System.
Produce a fully patched secure version of the code.

CRITICAL: The patched_code value must be a single-line JSON string. 
Replace all newlines in the code with \\n, all quotes with \\".

Respond ONLY in this JSON format (no markdown, no preamble, no extra text):
{
  "patched_code": "import sqlite3\\nimport os\\n...",
  "changes": [
    {
      "vulnerability": "what was fixed",
      "fix_description": "how you fixed it"
    }
  ]
}"""

AGENT_4_SYSTEM = """You are a patch verification agent in a Cyber Reasoning System.
Verify if the patch resolves ALL vulnerabilities without introducing new ones.

Respond ONLY in this JSON format (no markdown, no preamble, no extra text):
{
  "verdict": "PASS",
  "resolved": [
    {"vulnerability": "type", "resolved": true, "reason": "why"}
  ],
  "new_issues": [],
  "confidence": 95
}"""


def run_crs(code: str) -> dict:
    a1_raw = run_agent(AGENT_1_SYSTEM, f"Analyze this code:\n\n{code}")
    a1 = json.loads(a1_raw)

    a2_raw = run_agent(AGENT_2_SYSTEM, f"Code:\n{code}\n\nVulnerabilities:\n{json.dumps(a1, indent=2)}")
    a2 = json.loads(a2_raw)

    a3_raw = run_agent(AGENT_3_SYSTEM, f"Vulnerable code:\n{code}\n\nVulnerabilities:\n{json.dumps(a1, indent=2)}")
    a3 = json.loads(a3_raw)

    a4_raw = run_agent(AGENT_4_SYSTEM, f"Original:\n{code}\n\nPatched:\n{a3['patched_code']}\n\nVulnerabilities:\n{json.dumps(a1, indent=2)}")
    a4 = json.loads(a4_raw)

    return {
        "static_analysis": a1,
        "classification": a2,
        "patch": a3,
        "verification": a4
    }
