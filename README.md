SentinelZero Agent Arena

Autonomous AI Email Security Agent

SentinelZero is an autonomous Tier-1 SOC email security agent built for the SentinelZero Agent Arena competition.

The agent investigates suspicious email messages using sender identity, domain reputation, email authentication headers, approved-domain policies, and thread history. It then classifies the message, selects an appropriate security action, gathers evidence, and produces a structured analyst-style response.

1. Problem Overview

The objective of the competition is to build an autonomous AI email security agent capable of handling suspicious-email investigations.

For each task, the agent receives an email and investigates available security information before deciding whether to:

Allow and deliver the message

Apply a warning banner

Quarantine the message

Escalate to Tier-2 SOC

The agent must make evidence-grounded decisions while resisting malicious instructions contained inside email bodies.

2. Agent Workflow

The SentinelZero workflow is:

Incoming Email
      |
      v
Parse Email Metadata
      |
      v
+---------------------------+
| Security Investigation    |
|                           |
| - Sender Directory        |
| - Approved Domains        |
| - Email Headers           |
| - Domain Reputation       |
| - Thread History          |
+---------------------------+
      |
      v
Analyze Security Signals
      |
      +----------------------+
      |                      |
      v                      v
Authentication          Sender / Domain
SPF / DKIM / DMARC       Verification
      |                      |
      +----------+-----------+
                 |
                 v
          Content Analysis
                 |
                 +----------------------+
                 |                      |
                 v                      v
       Phishing / Fraud        Prompt Injection
       Malware / BEC           Detection
                 |                      |
                 +----------+-----------+
                            |
                            v
                    Evidence Ledger
                            |
                            v
                    Risk Classification
                            |
                            v
              +-------------+-------------+
              |             |             |
              v             v             v
            Allow         Warn      Quarantine
                                      |
                                      v
                                  Escalate
                             when evidence requires
                             Tier-2 investigation

3. Investigation Tools

The agent uses the supplied Arena tools to gather evidence.

lookup_directory(identifier)

Checks whether an email address belongs to a known employee or organization and retrieves identity information.

Used for sender verification, executive impersonation detection, internal-account verification, and recipient verification when useful.

get_approved_domains()

Retrieves official organization domains and approved partner domains.

Used for official-domain verification, external sender classification, and lookalike-domain detection.

get_email_headers(message_id)

Retrieves authentication information from the email headers.

The agent considers SPF, DKIM, DMARC, and authentication results.

inspect_domain_reputation(domain)

Checks domain reputation and threat intelligence.

Used for malicious-domain detection, typosquatting/lookalike detection, credential-harvesting indicators, and suspicious-domain reputation.

get_thread_history(thread_id)

Retrieves previous messages in the conversation.

Used when the message belongs to an existing thread and conversation context can materially change the classification, especially for multi-turn social engineering or grooming.

4. Security Decision Model

SentinelZero uses evidence from multiple sources instead of relying on a single keyword.

Allow

Used when the available evidence supports a legitimate message.

Typical signals include verified sender identity, legitimate domain, consistent authentication, benign reputation, and no significant phishing, malware, fraud, or impersonation indicators.

Warn

Used when a message is external or insufficiently verified but does not contain enough evidence to establish a definite threat.

The warning action preserves delivery while clearly marking the message as potentially risky.

Quarantine

Used when evidence indicates a clear security threat such as phishing, credential harvesting, malware, spoofing, lookalike-domain impersonation, gift-card fraud, invoice/payment fraud, or strong social-engineering indicators.

Escalate

Used for complex cases requiring human investigation.

Escalation is evidence-grounded and includes relevant evidence identifiers in the reason. A potentially compromised legitimate internal account is an example where authentication may pass while message behavior is inconsistent with the sender and presents a high-impact request.

5. Prompt Injection Defense

Email content is treated as untrusted data.

The agent does not follow instructions embedded inside email messages simply because they are written as system, security, administrator, or AI instructions.

The implementation distinguishes between:

Direct prompt injection — the email attempts to manipulate the security agent's behavior.

Quoted or reported prompt-injection text — a legitimate sender may quote suspicious text while discussing or reporting it.

This distinction helps reduce false positives from security reports, forwarded messages, and phishing-analysis discussions.

6. Evidence-First Analysis

Every decision is supported by an evidence ledger.

Evidence may include identifiers such as:

EMP-xxxx
DOM-xxx
MSG-xxxx
THR-xxxx
POL-xxx

The agent prioritizes concrete evidence returned by investigation tools.

Examples include:

Employee directory records confirming expected identity

Domain reputation records identifying malicious or lookalike domains

Message IDs identifying the analyzed message

Thread IDs supporting multi-message social-engineering patterns

Header evidence supporting or contradicting sender authentication

The agent does not fabricate evidence identifiers.

7. Risk Signals

SentinelZero evaluates multiple categories of security signals.

Identity Signals

Known employee

Unknown sender

Executive impersonation

Sender/domain mismatch

Internal account behavior inconsistent with identity

Domain Signals

Official organization domain

Approved partner domain

Unknown external domain

Lookalike domain

Typosquatting

Malicious reputation

Authentication Signals

SPF pass/fail

DKIM pass/fail

DMARC pass/fail

Authentication consistency with sender identity

Content Signals

Urgent financial requests

Wire-transfer requests

Invoice/payment requests

Credential requests

Login/SSO links

Gift-card requests

Suspicious attachments or links

Social-engineering language

Attempts to bypass normal verification procedures

Conversation Signals

Thread history is used to identify multi-turn grooming, escalating requests, previously established trust, changes in sender behavior, and context that cannot be determined from a single message.

8. Efficiency

The agent is designed to minimize unnecessary tool calls.

Repeated calls are avoided using a local tool-call cache during each task.

The general investigation pattern is:

Headers
Domain Reputation
Sender Directory
Approved Domains
Thread History (when relevant)
Optional recipient verification
One security action

Thread history is not queried when there is no meaningful thread context.

This keeps investigations fast while maintaining investigation coverage.

9. Structured Output

The agent returns a structured result containing:

case_classification
decision
evidence
uncertainties
customer_response
confidence
prompt_injection_detected

Case classification

Contains:

category

issue

severity

Decision

Contains:

resolution

escalation_required

Possible resolutions:

allow
warn
quarantine
escalate

Evidence

A list of concrete evidence identifiers supporting the decision.

Uncertainties

Records relevant information that could not be established confidently.

Confidence

A value between 0 and 1 representing confidence in the classification.

Prompt Injection Flag

prompt_injection_detected: true | false

10. Project Structure

sentinelzero-agent-arena/
│
├── agent.py
├── main.py
├── README.md
├── AGENT.md
├── PROBLEM_STATEMENT.md
├── requirements.txt
├── .env.example
├── .gitignore
│
├── sdk/
│   ├── __init__.py
│   └── tools_client.py
│
├── mock_simulator/
│   ├── server.py
│   ├── requirements.txt
│   └── data/
│       ├── directory.json
│       ├── domains.json
│       ├── ground_truth.json
│       ├── historical_threats.json
│       ├── security_policies.json
│       ├── tasks.json
│       └── threat_intel.json
│
└── sample_data/
    ├── README.md
    ├── directory.csv
    ├── domains.csv
    ├── ground_truth.csv
    ├── historical_threats.csv
    ├── security_policies.csv
    ├── tasks.csv
    └── threat_intel.csv

Only agent.py contains the competition agent implementation.

11. Local Practice Mode

The repository includes the supplied mock simulator for local development and validation.

Install dependencies

Create and activate a virtual environment:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Install requirements:

pip install -r requirements.txt

Start the mock simulator

From the project root:

python mock_simulator/server.py --port 8001

The simulator runs at:

http://127.0.0.1:8001

Run practice tasks

For a single task:

python main.py --mode practice --once

For the complete local benchmark:

python main.py --mode practice --max-tasks 30

The practice environment is intended for validating the agent implementation before Arena submission.

12. Configuration

Runtime configuration is provided through environment variables.

Use .env.example as the configuration template.

Example:

MODE=practice

PRACTICE_ARENA_URL=http://127.0.0.1:8001
PRACTICE_BEARER_TOKEN=dev-practice-token

SUBMISSION_ARENA_URL=<arena-url>
SUBMISSION_BEARER_TOKEN=<arena-token>

GOOGLE_API_KEY_1=<optional>
GOOGLE_API_KEY_2=<optional>
GOOGLE_API_KEY_3=<optional>
GOOGLE_API_KEY_4=<optional>
GOOGLE_API_KEY_5=<optional>

GEMINI_MODEL=gemini-3.5-flash-lite

Secrets are stored locally in .env and are excluded from version control.

13. Live Submission

Live Arena submission is performed through the supplied main.py entry point.

The live bearer token must remain private and must never be committed to GitHub.

Before submitting, verify that:

git status

does not show .env.

The .gitignore file excludes local credentials and development artifacts.

14. Design Principles

Evidence over assumptions

The agent bases security decisions on tool-returned evidence and observable message signals.

Defense in depth

No single signal determines every classification.

Sender identity, authentication, domain reputation, thread context, and message content are considered together.

Least privilege

The agent performs only the investigation and security action required for the current task.

Untrusted email content

Email bodies are treated as potentially malicious input and never as trusted system instructions.

Deterministic safety boundaries

High-confidence security indicators and action mappings are implemented with explicit rules so that critical decisions remain predictable.

Explainability

The final response explains why an action was taken and identifies the evidence supporting it.

Efficiency

Repeated tool calls are avoided while preserving investigation coverage.

15. Security Scenarios Covered

The implementation is designed to handle scenarios including:

Executive impersonation

Fake invoices

Urgent external inquiries

Credential harvesting

Fake SSO/login requests

Gift-card scams

Multi-turn social engineering

Lookalike and typosquatted domains

Legitimate internal communication

Legitimate external partners

Prompt injection attempts

Compromised internal accounts

Quoted prompt-injection text

Authentication failures

Suspicious domain reputation

Business email compromise indicators

16. Development Approach

The implementation follows a layered approach:

Input Normalization
        ↓
Security Tool Investigation
        ↓
Evidence Extraction
        ↓
Authentication Analysis
        ↓
Identity / Domain Analysis
        ↓
Content & Conversation Analysis
        ↓
Prompt Injection Analysis
        ↓
Risk Classification
        ↓
Security Action
        ↓
Evidence-Grounded Response

The design intentionally avoids unnecessary architectural complexity. The primary objective is reliable autonomous SOC triage with strong evidence and efficient tool usage.

17. Validation

The agent was tested locally against the supplied 30-task practice benchmark.

The current implementation achieved:

30 / 30 tasks passed
100% practice benchmark result

The practice benchmark includes multiple classes of email-security scenarios, including phishing, impersonation, legitimate messages, social engineering, prompt injection, and compromised-account behavior.

Practice results are used for development validation and are not treated as a substitute for hidden Arena evaluation.

18. Competition Submission

The repository contains:

Agent implementation

Runner

SDK client

Mock simulator

Sample data

Configuration template

Documentation

No local virtual environment or secret credentials are included in the repository.

The repository is intended to be publicly accessible for jury evaluation.

19. Team

Team: Peaky Blinders

Project: SentinelZero Agent Arena

Focus: Autonomous AI-powered email security triage and Tier-1 SOC automation.

20. Summary

SentinelZero treats every incoming email as an investigation rather than simply a classification problem.

The agent:

Parses the email.

Verifies sender identity.

Checks approved domains.

Inspects authentication headers.

Checks domain reputation.

Uses thread history when relevant.

Detects phishing, fraud, impersonation, and social-engineering signals.

Defends against prompt injection.

Builds an evidence-backed assessment.

Selects the appropriate security action.

Returns a structured, explainable SOC response.

The result is a lightweight autonomous email-security agent designed to make fast, evidence-grounded Tier-1 SOC decisions.