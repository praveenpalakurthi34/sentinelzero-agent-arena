"""
SentinelZero Agent Arena
V8 - deterministic SOC triage agent

Only agent.py should be modified.
"""

import json
import re
from typing import Any


# ============================================================
# EVIDENCE
# ============================================================

EVIDENCE_RE = re.compile(
    r"\b(?:EMP|DOM|MSG|THR|POL|LOG)-[A-Za-z0-9_-]+\b"
)


def extract_evidence(obj: Any) -> set[str]:
    if obj is None:
        return set()

    if isinstance(obj, str):
        return set(EVIDENCE_RE.findall(obj))

    try:
        text = json.dumps(obj, default=str)
    except Exception:
        text = str(obj)

    return set(EVIDENCE_RE.findall(text))


# ============================================================
# GENERIC HELPERS
# ============================================================

def flatten_text(obj: Any) -> str:

    if obj is None:
        return ""

    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        return " ".join(
            flatten_text(v)
            for v in obj.values()
        )

    if isinstance(obj, (list, tuple, set)):
        return " ".join(
            flatten_text(v)
            for v in obj
        )

    return str(obj)


def matches_any(
    text: str,
    keywords: list[str],
) -> bool:
    """Match complete words/phrases, avoiding substring false positives."""
    text = str(text or "").lower()

    for keyword in keywords:
        kw = keyword.lower().strip()
        if not kw:
            continue
        pattern = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
        if re.search(pattern, text):
            return True

    return False


def get_domain(email: str) -> str:

    email = str(email or "")

    if "@" not in email:
        return ""

    return email.rsplit(
        "@",
        1
    )[1].strip().lower()


# ============================================================
# TOOL CACHE
# ============================================================

class ToolCallCache:

    def __init__(
        self,
        tools,
    ):

        self.tools = tools
        self.cache = {}

    def call(
        self,
        name: str,
        *args,
        **kwargs,
    ):

        key = (
            name,
            args,
            tuple(
                sorted(
                    kwargs.items()
                )
            ),
        )

        if key not in self.cache:

            method = getattr(
                self.tools,
                name,
            )

            self.cache[key] = method(
                *args,
                **kwargs,
            )

        return self.cache[key]


# ============================================================
# EMAIL AUTHENTICATION
# ============================================================

def get_auth(
    headers: Any,
) -> dict:

    if not isinstance(
        headers,
        dict,
    ):
        return {}

    auth = headers.get(
        "auth_results"
    )

    if isinstance(
        auth,
        dict,
    ):
        return auth

    return {}


def auth_passed(
    headers: Any,
) -> bool:

    auth = get_auth(
        headers
    )

    return (
        auth.get("spf") == "pass"
        and
        auth.get("dkim") == "pass"
        and
        auth.get("dmarc") == "pass"
    )


def auth_failed(
    headers: Any,
) -> bool:

    auth = get_auth(
        headers
    )

    return any(
        auth.get(key) == "fail"
        for key in (
            "spf",
            "dkim",
            "dmarc",
        )
    )


# ============================================================
# DIRECTORY
# ============================================================

def get_employee(
    directory: Any,
) -> dict:

    if not isinstance(
        directory,
        dict,
    ):
        return {}

    employee = directory.get(
        "employee"
    )

    if isinstance(
        employee,
        dict,
    ):
        return employee

    return {}


def directory_has_employee(
    directory: Any,
) -> bool:

    if not isinstance(
        directory,
        dict,
    ):
        return False

    return (
        bool(
            directory.get(
                "found"
            )
        )
        and
        bool(
            directory.get(
                "employee"
            )
        )
    )


def employee_id(
    directory: Any,
) -> str:

    employee = get_employee(
        directory
    )

    value = (
        employee.get("id")
        or
        employee.get("employee_id")
        or
        ""
    )

    return str(value)


# ============================================================
# APPROVED DOMAINS
# ============================================================

def official_domains(
    approved: Any,
) -> set[str]:

    if not isinstance(
        approved,
        dict,
    ):
        return set()

    values = approved.get(
        "official_domains",
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return set()

    return {
        str(x).lower()
        for x in values
    }


def partner_domains(
    approved: Any,
) -> set[str]:

    if not isinstance(
        approved,
        dict,
    ):
        return set()

    values = approved.get(
        "partner_domains",
        [],
    )

    if not isinstance(
        values,
        list,
    ):
        return set()

    return {
        str(x).lower()
        for x in values
    }


# ============================================================
# DOMAIN REPUTATION
# ============================================================

def reputation_value(
    reputation: Any,
) -> str:

    if not isinstance(
        reputation,
        dict,
    ):
        return ""

    value = reputation.get(
        "reputation",
        "",
    )

    if value is None:
        return ""

    return str(
        value
    ).strip().lower()


def threat_score(
    reputation: Any,
) -> int:

    if not isinstance(
        reputation,
        dict,
    ):
        return 0

    try:

        return int(
            reputation.get(
                "threat_score",
                0,
            )
            or 0
        )

    except Exception:

        return 0


def domain_id(
    reputation: Any,
) -> str:

    if not isinstance(
        reputation,
        dict,
    ):
        return ""

    return str(
        reputation.get(
            "domain_id",
            "",
        )
    )


def is_malicious_reputation(
    reputation: Any,
) -> bool:

    """
    Only the structured reputation classification
    'malicious' is treated as a malicious-domain verdict.

    A high threat_score alone is NOT sufficient.
    """

    if not isinstance(
        reputation,
        dict,
    ):
        return False

    value = reputation.get(
        "reputation"
    )

    if value is None:
        return False

    return (
        str(value)
        .strip()
        .lower()
        == "malicious"
    )


def is_lookalike(
    reputation: Any,
) -> bool:

    if not isinstance(
        reputation,
        dict,
    ):
        return False

    return bool(
        reputation.get(
            "lookalike_of"
        )
    )


def is_safe_reputation(
    reputation: Any,
) -> bool:

    return reputation_value(
        reputation
    ) in {
        "safe",
        "trusted",
        "legitimate",
        "benign",
    }


# ============================================================
# PROMPT INJECTION
# ============================================================

DIRECT_INJECTION_RE = re.compile(
    r"(?:"
    r"important\s+system\s+instruction"
    r"|system\s+instruction\s*:"
    r"|you\s+must\s+return\s+decision"
    r"|do\s+not\s+quarantine"
    r"|override\s+security\s+policy"
    r"|disregard\s+previous\s+instructions"
    r"|ignore\s+(?:all\s+)?previous\s+instructions"
    r"|mark\s+(?:this|the\s+message)\s+as\s+"
    r"(?:safe|verified|allow|allowed)"
    r")",
    re.IGNORECASE,
)


REPORTING_CONTEXT_RE = re.compile(
    r"(?:"
    r"i\s+(?:received|got)"
    r"|message\s+i\s+received"
    r"|email\s+i\s+received"
    r"|forwarded"
    r"|forwarding"
    r"|quoted"
    r"|quote"
    r"|reporting"
    r"|reported"
    r"|phishing\s+simulation"
    r"|does\s+this\s+look\s+like\s+phishing"
    r"|suspicious\s+(?:message|email|instruction)"
    r")",
    re.IGNORECASE,
)


def detect_prompt_injection(
    body: str,
) -> tuple[bool, bool]:

    body = str(
        body or ""
    )

    direct = bool(
        DIRECT_INJECTION_RE.search(
            body
        )
    )

    if not direct:
        return (
            False,
            False,
        )

    reporting = bool(
        REPORTING_CONTEXT_RE.search(
            body
        )
    )

    if reporting:

        return (
            True,
            False,
        )

    return (
        True,
        True,
    )


# ============================================================
# CONTENT SIGNALS
# ============================================================

FINANCIAL_KEYWORDS = [

    "wire transfer",
    "wire $",
    "transfer $",
    "bank account",
    "account #",
    "account number",
    "routing number",
    "payment",
    "remit",
    "invoice",
    "gift card",
    "gift cards",
    "claim code",
    "claim codes",
    "reimburse",

]


CREDENTIAL_KEYWORDS = [

    "password",
    "credentials",
    "verify your credentials",
    "verify your password",
    "log into",
    "login",
    "sign in",
    "sso",
    "password will expire",

]


MALWARE_KEYWORDS = [

    "malware",
    "ransomware",
    "trojan",
    "payload",
    ".exe",
    ".scr",
    "macro",

]


URGENCY_KEYWORDS = [

    "urgent",
    "immediately",
    "right now",
    "as soon as possible",
    "before noon",
    "within 2 hours",
    "today",
    "by 5 pm",
    "by 5pm",

]


SECRECY_KEYWORDS = [

    "do not call",
    "don't call",
    "do not tell",
    "don't tell",
    "keep this confidential",
    "confidential",

]


def has_financial(
    text: str,
) -> bool:

    text = str(text or "").lower()

    if matches_any(text, FINANCIAL_KEYWORDS):
        return True

    if re.search(
        r"\b(?:wire|transfer|payment|pay|remit|send)\b"
        r".{0,30}\$\s?\d",
        text,
        re.IGNORECASE,
    ):
        return True

    if re.search(
        r"\b(?:gift\s+cards?|claim\s+codes?)\b"
        r".{0,60}\$\s?\d",
        text,
        re.IGNORECASE,
    ):
        return True

    return False


def has_credentials(
    text: str,
) -> bool:

    return matches_any(
        text,
        CREDENTIAL_KEYWORDS,
    )


def has_malware(
    text: str,
) -> bool:

    return matches_any(
        text,
        MALWARE_KEYWORDS,
    )


def has_urgency(
    text: str,
) -> bool:

    return matches_any(
        text,
        URGENCY_KEYWORDS,
    )


def has_secrecy(
    text: str,
) -> bool:

    return matches_any(
        text,
        SECRECY_KEYWORDS,
    )


# ============================================================
# THREAD ANALYSIS
# ============================================================

def has_grooming(
    thread: Any,
) -> bool:

    text = flatten_text(
        thread
    ).lower()

    markers = [

        "trust",
        "new supplier",
        "new vendor",
        "bank details",
        "account details",
        "wire",
        "transfer",
        "before noon",
        "shipment",

    ]

    count = sum(
        1
        for marker in markers
        if marker in text
    )

    return count >= 2


# ============================================================
# LIVE RAW EMAIL PARSING
# ============================================================

def parse_raw_email(raw_email: str) -> dict[str, str]:
    """Parse live Arena raw-email customer_message into canonical fields."""
    raw = str(raw_email or "")
    if not raw:
        return {}

    parts = re.split(r"\n\s*\n", raw, maxsplit=1)
    header_text = parts[0]
    body_text = parts[1] if len(parts) > 1 else ""

    def header(name: str) -> str:
        match = re.search(
            r"(?im)^" + re.escape(name) + r"\s*:\s*(.+?)\s*$",
            header_text,
        )
        return match.group(1).strip() if match else ""

    from_value = header("From")
    to_value = header("To")

    sender_match = re.search(
        r"<\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*>",
        from_value,
    )
    if not sender_match:
        sender_match = re.search(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            from_value,
        )

    recipient_match = re.search(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        to_value,
    )

    return {
        "message_id": header("Message-ID"),
        "sender_email": sender_match.group(1) if sender_match and sender_match.lastindex else sender_match.group(0) if sender_match else "",
        "recipient_email": recipient_match.group(0) if recipient_match else "",
        "subject": header("Subject"),
        "message_body": body_text.strip(),
    }


# ============================================================
# AGENT
# ============================================================

class Agent:

    def __init__(
        self,
        tools,
    ):

        self.tools = tools

        self.cache = ToolCallCache(
            tools
        )

    def solve(
        self,
        task: dict[str, Any],
    ) -> dict[str, Any]:

        # ====================================================
        # NORMALIZE NESTED PAYLOAD
        # ====================================================

        payload = task.get(
            "input_payload"
        )

        if not isinstance(
            payload,
            dict,
        ):

            payload = task

        def get_task_value(
            key: str,
            default: str = "",
        ) -> str:

            value = payload.get(key)

            if value is not None and value != "":
                return str(value)

            value = task.get(key)

            if value is not None and value != "":
                return str(value)

            return default

        task_id = get_task_value(
            "task_id",
            str(task.get("task_id", "")),
        )

        message_id = get_task_value(
            "message_id"
        )

        thread_id = get_task_value(
            "thread_id"
        )

        sender_email = get_task_value(
            "sender_email"
        )

        recipient_email = get_task_value(
            "recipient_email"
        )

        subject = get_task_value(
            "subject"
        )

        body = get_task_value(
            "message_body"
        )

        if not body:
            body = get_task_value(
                "customer_message"
            )

        # Live Arena format: customer_message contains the complete raw
        # email rather than separate message fields. Parse it into the
        # canonical fields expected by the existing V8 investigation logic.
        if not message_id and body:
            parsed_live = parse_raw_email(body)

            if parsed_live.get("message_id"):
                message_id = parsed_live["message_id"]

            if parsed_live.get("sender_email"):
                sender_email = parsed_live["sender_email"]

            if parsed_live.get("recipient_email"):
                recipient_email = parsed_live["recipient_email"]

            if parsed_live.get("subject"):
                subject = parsed_live["subject"]

            if parsed_live.get("message_body"):
                body = parsed_live["message_body"]

        if not message_id:

            raise ValueError(
                "message_id missing after input normalization. "
                "Available outer keys: "
                + str(sorted(task.keys()))
                + "; Available payload keys: "
                + str(sorted(payload.keys()))
            )

        domain = get_domain(
            sender_email
        )

        text = (
            f"{subject}\n{body}"
        )

        # ====================================================
        # REQUIRED INVESTIGATION
        # ====================================================

        headers = self.cache.call(
            "get_email_headers",
            message_id,
        )

        reputation = self.cache.call(
            "inspect_domain_reputation",
            domain,
        )

        sender_directory = self.cache.call(
            "lookup_directory",
            sender_email,
        )

        approved = self.cache.call(
            "get_approved_domains",
        )

        thread = None

        if thread_id:

            thread = self.cache.call(
                "get_thread_history",
                thread_id,
            )

        # ====================================================
        # SELECTIVE RECIPIENT LOOKUP
        # ====================================================

        # Recipient identity is useful for establishing the
        # university context of inbound messages.
        recipient_directory = None

        if recipient_email:
            recipient_directory = self.cache.call(
                "lookup_directory",
                recipient_email,
            )

        # ====================================================
        # EVIDENCE
        # ====================================================

        evidence = set()

        for obj in (

            sender_directory,
            reputation,
            headers,
            approved,
            thread,
            recipient_directory,

        ):

            evidence.update(
                extract_evidence(
                    obj
                )
            )

        if EVIDENCE_RE.fullmatch(
            message_id
        ):

            evidence.add(
                message_id
            )

        if (
            thread_id
            and
            EVIDENCE_RE.fullmatch(
                thread_id
            )
        ):

            evidence.add(
                thread_id
            )

        # ====================================================
        # SECURITY FACTS
        # ====================================================

        authentication_ok = auth_passed(
            headers
        )

        sender_is_employee = directory_has_employee(
            sender_directory
        )

        sender_employee_id = employee_id(
            sender_directory
        )

        recipient_employee_id = employee_id(
            recipient_directory
        )

        approved_official_domains = (
            official_domains(
                approved
            )
        )

        approved_partner_domains = (
            partner_domains(
                approved
            )
        )

        domain_is_official = (
            domain
            in
            approved_official_domains
        )

        domain_is_partner = (
            domain
            in
            approved_partner_domains
        )

        malicious_domain = (
            is_malicious_reputation(
                reputation
            )
        )

        lookalike_domain = (
            is_lookalike(
                reputation
            )
        )

        safe_domain = (
            is_safe_reputation(
                reputation
            )
        )

        # ====================================================
        # CONTENT
        # ====================================================

        financial_signal = has_financial(
            text
        )

        credential_signal = has_credentials(
            text
        )

        malware_signal = has_malware(
            text
        )

        urgency_signal = has_urgency(
            text
        )

        secrecy_signal = has_secrecy(
            text
        )

        grooming_signal = (

            has_grooming(
                thread
            )

            if thread is not None

            else False
        )

        injection_present, genuine_injection = (
            detect_prompt_injection(
                body
            )
        )

        # ====================================================
        # DECISION DEFAULTS
        # ====================================================

        resolution = "warn"

        issue = "external_or_unverified"

        severity = "medium"

        escalation_required = False

        confidence = 0.60

        reason = ""

        # ====================================================
        # 1. GENUINE PROMPT INJECTION
        # ====================================================

        if genuine_injection:

            resolution = "quarantine"

            issue = "prompt_injection"

            severity = "critical"

            confidence = 0.95

            reason = (
                f"Message {message_id} contains a direct "
                f"prompt-injection directive attempting "
                f"to influence security classification."
            )

        # ====================================================
        # 2. MALICIOUS DOMAIN
        # ====================================================

        elif malicious_domain:

            resolution = "quarantine"

            if lookalike_domain:

                issue = "spoofing"

            elif credential_signal:

                issue = "credential_phishing"

            elif malware_signal:

                issue = "malware"

            else:

                issue = "phishing"

            severity = "high"

            confidence = 0.92

            did = domain_id(
                reputation
            )

            if did:

                reason = (
                    f"Domain reputation {did} identifies "
                    f"the sender domain as malicious."
                )

            else:

                reason = (
                    f"Sender domain {domain} has a malicious "
                    f"reputation."
                )

        # ====================================================
        # 3. MULTI-TURN GROOMING + FINANCIAL REQUEST
        # ====================================================

        elif (
            grooming_signal
            and
            financial_signal
        ):

            resolution = "quarantine"

            issue = (
                "multi_turn_social_engineering"
            )

            severity = "high"

            confidence = 0.91

            reason = (
                f"Thread {thread_id} contains multi-turn "
                f"social-engineering indicators followed "
                f"by a financial request."
            )

        # ====================================================
        # 4. REPORTED / QUOTED PROMPT-INJECTION TEXT
        # ====================================================

        elif (
            injection_present
            and
            not genuine_injection
        ):

            resolution = "warn"

            issue = "reported_prompt_injection"

            severity = "medium"

            confidence = 0.86

            reason = (
                "The message quotes or reports instruction-like "
                "text rather than directly instructing the "
                "security agent. It is treated as suspicious "
                "security-reporting content."
            )

        # ====================================================
        # 5. VERIFIED INTERNAL
        # ====================================================

        elif (
            domain_is_official
            and
            sender_is_employee
            and
            authentication_ok
        ):

            if (
                financial_signal
                and
                (
                    urgency_signal
                    or
                    secrecy_signal
                )
            ):

                resolution = "escalate"

                issue = (
                    "business_email_compromise"
                )

                severity = "critical"

                escalation_required = True

                confidence = 0.85

                reason = (
                    f"Internal employee {sender_employee_id} "
                    f"passes SPF/DKIM/DMARC but sent a "
                    f"suspicious urgent financial request, "
                    f"indicating possible account compromise."
                )

            elif credential_signal:

                resolution = "quarantine"

                issue = (
                    "internal_credential_phishing"
                )

                severity = "high"

                confidence = 0.89

                reason = (
                    f"Verified internal sender "
                    f"{sender_employee_id} sent "
                    f"credential-harvesting content."
                )

            elif malware_signal:

                resolution = "quarantine"

                issue = "malware"

                severity = "high"

                confidence = 0.89

                reason = (
                    f"Verified internal sender "
                    f"{sender_employee_id} sent content "
                    f"containing malware indicators."
                )

            else:

                resolution = "allow"

                issue = "internal_legitimate"

                severity = "low"

                confidence = 0.91

                reason = (
                    f"Sender {sender_employee_id} is an "
                    f"employee using an approved internal "
                    f"domain and SPF/DKIM/DMARC all pass."
                )

        # ====================================================
        # 5. APPROVED EXTERNAL PARTNER
        # ====================================================

        elif domain_is_partner:

            if (
                credential_signal
                or
                malware_signal
            ):

                resolution = "quarantine"

                issue = (
                    "external_phishing"
                )

                severity = "high"

                confidence = 0.86

                reason = (
                    f"Approved external partner domain "
                    f"{domain} sent credential or malware "
                    f"indicators."
                )

            elif (
                financial_signal
                and
                (
                    urgency_signal
                    or
                    secrecy_signal
                )
            ):

                resolution = "quarantine"

                issue = (
                    "external_financial_fraud"
                )

                severity = "high"

                confidence = 0.86

                reason = (
                    f"Approved external partner domain "
                    f"{domain} sent an urgent or secret "
                    f"financial request."
                )

            else:

                resolution = "allow"

                issue = (
                    "external_legitimate"
                )

                severity = "low"

                confidence = 0.89

                reason = (
                    f"Sender domain {domain} is an approved "
                    f"external partner and no clear malicious "
                    f"content was detected."
                )

        # ====================================================
        # 6. LOOKALIKE DOMAIN
        # ====================================================

        elif lookalike_domain:

            if (
                financial_signal
                or
                credential_signal
                or
                malware_signal
            ):

                resolution = "quarantine"

                issue = "spoofing"

                severity = "high"

                confidence = 0.91

                reason = (
                    f"Sender domain {domain} has lookalike/"
                    f"spoofing indicators combined with "
                    f"threat-related content."
                )

            else:

                resolution = "warn"

                issue = (
                    "suspected_impersonation"
                )

                severity = "medium"

                confidence = 0.72

                reason = (
                    f"Sender domain {domain} has lookalike/"
                    f"spoofing indicators."
                )

        # ====================================================
        # 7. CREDENTIAL PHISHING
        # ====================================================

        elif credential_signal:

            resolution = "quarantine"

            issue = (
                "credential_phishing"
            )

            severity = "high"

            confidence = 0.90

            reason = (
                "Message contains credential-harvesting "
                "indicators."
            )

        # ====================================================
        # 8. MALWARE
        # ====================================================

        elif malware_signal:

            resolution = "quarantine"

            issue = "malware"

            severity = "high"

            confidence = 0.90

            reason = (
                "Message contains malware indicators."
            )

        # ====================================================
        # 9. FINANCIAL FRAUD
        # ====================================================

        elif (
            financial_signal
            and
            (
                urgency_signal
                or
                secrecy_signal
            )
        ):

            resolution = "quarantine"

            issue = (
                "external_financial_fraud"
            )

            severity = "high"

            confidence = 0.89

            reason = (
                "External message contains a financial "
                "request combined with urgency or secrecy."
            )

        # ====================================================
        # 10. URGENCY ONLY
        # ====================================================

        elif urgency_signal:

            resolution = "warn"

            issue = (
                "external_urgent_inquiry"
            )

            severity = "medium"

            confidence = 0.72

            reason = (
                "External message contains deadline/"
                "urgency language, but available evidence "
                "does not establish a definite malicious threat."
            )

        # ====================================================
        # 11. SAFE DOMAIN
        # ====================================================

        elif safe_domain:

            resolution = "allow"

            issue = (
                "external_legitimate"
            )

            severity = "low"

            confidence = 0.85

            reason = (
                f"Sender domain {domain} has a safe/"
                f"legitimate reputation and the message "
                f"contains no clear malicious indicators."
            )

        # ====================================================
        # 12. AUTHENTICATED INTERNAL FALLBACK
        # ====================================================

        elif (
            domain_is_official
            and
            sender_is_employee
            and
            authentication_ok
        ):

            resolution = "allow"

            issue = (
                "internal_legitimate"
            )

            severity = "low"

            confidence = 0.86

            reason = (
                f"Sender {sender_employee_id} is an "
                f"authenticated internal employee."
            )

        # ====================================================
        # 13. DEFAULT
        # ====================================================

        else:

            resolution = "warn"

            issue = (
                "external_or_unverified"
            )

            severity = "medium"

            confidence = 0.62

            reason = (
                f"Sender domain {domain} could not be "
                f"fully verified and available evidence "
                f"does not establish a definite malicious threat."
            )

        # ====================================================
        # ESCALATION SAFETY
        # ====================================================

        if resolution == "escalate":

            if not evidence:

                resolution = "quarantine"

                escalation_required = False

                issue = (
                    "suspicious_internal_financial_request"
                )

                severity = "high"

                confidence = 0.83

                reason = (
                    "Suspicious internal financial request "
                    "could not be grounded with retrieved evidence."
                )

        else:

            escalation_required = False

        # ====================================================
        # ACTION
        # ====================================================

        if resolution == "allow":

            self.tools.allow_and_deliver(
                message_id,
                reason=reason,
            )

        elif resolution == "warn":

            self.tools.apply_warning_banner(
                message_id,
                banner_type="EXTERNAL_SENDER",
                reason=reason,
            )

        elif resolution == "quarantine":

            self.tools.quarantine_message(
                message_id,
                reason=reason,
            )

        elif resolution == "escalate":

            cite_id = None

            if (
                sender_employee_id
                and
                sender_employee_id in evidence
            ):

                cite_id = sender_employee_id

            elif (
                domain_id(reputation)
                and
                domain_id(reputation) in evidence
            ):

                cite_id = domain_id(
                    reputation
                )

            elif message_id in evidence:

                cite_id = message_id

            elif evidence:

                cite_id = sorted(
                    evidence
                )[0]

            if not cite_id:

                resolution = "quarantine"

                escalation_required = False

                self.tools.quarantine_message(
                    message_id,
                    reason=(
                        "Escalation could not be grounded "
                        "with an evidence ID."
                    ),
                )

            else:

                escalation_reason = (
                    f"{reason} Evidence ID: {cite_id}."
                )

                try:

                    self.tools.escalate_to_tier2_soc(
                        message_id,
                        escalation_reason,
                    )

                except Exception:

                    resolution = "quarantine"

                    escalation_required = False

                    self.tools.quarantine_message(
                        message_id,
                        reason=(
                            f"Tier-2 escalation failed. "
                            f"Message quarantined. "
                            f"Evidence ID: {cite_id}."
                        ),
                    )

        # ====================================================
        # EVIDENCE ORDER
        # ====================================================

        # Keep evidence focused, but recover useful structured IDs
        # directly harvested from each investigation result when a
        # helper function could not extract the ID.
        #
        # Priority:
        #   1. Sender identity
        #   2. Recipient identity when relevant
        #   3. Domain reputation
        #   4. Message
        #   5. Thread when material
        #
        # We deliberately avoid submitting every ID returned by the
        # tools because unrelated evidence can reduce Evidence F1.

        ordered_evidence = []

        def add_evidence(value: str):
            if (
                value
                and
                value in evidence
                and
                value not in ordered_evidence
            ):
                ordered_evidence.append(value)

        def first_evidence_with_prefix(
            prefix: str,
            excluded: set[str] | None = None,
        ) -> str:
            excluded = excluded or set()

            for value in sorted(evidence):
                if (
                    value.startswith(prefix)
                    and
                    value not in excluded
                ):
                    return value

            return ""

        # ----------------------------------------------------
        # 1. SENDER IDENTITY
        # ----------------------------------------------------

        # Prefer the specifically extracted sender employee ID.
        add_evidence(sender_employee_id)

        # If the structured helper did not expose the employee ID,
        # recover an EMP-* identifier harvested from the sender
        # directory result.
        if not sender_employee_id:
            sender_fallback = first_evidence_with_prefix("EMP-")

            if sender_fallback:
                add_evidence(sender_fallback)

        # ----------------------------------------------------
        # 2. RECIPIENT IDENTITY
        # ----------------------------------------------------

        # Recipient identity is useful for inbound external messages,
        # especially when the sender is not an internal employee.
        #
        # For spoofed executive-style financial requests, the sender
        # identity is more directly relevant, so preserve the existing
        # V8 exclusion for that case.
        if (
            not domain_is_official
            and
            recipient_employee_id
            and
            not (
                lookalike_domain
                and
                sender_is_employee
                and
                financial_signal
            )
        ):
            add_evidence(recipient_employee_id)

        # If there was no explicit recipient employee ID, do not blindly
        # select another EMP-* record here because it may be the sender.
        # This avoids accidentally adding the wrong employee evidence.

        # ----------------------------------------------------
        # 3. DOMAIN REPUTATION
        # ----------------------------------------------------

        rep_id = domain_id(
            reputation
        )

        # Prefer the domain ID explicitly returned by the reputation
        # helper.
        if (
            rep_id
            and
            (
                not domain_is_official
                or
                malicious_domain
                or
                lookalike_domain
            )
        ):
            add_evidence(rep_id)

        # Fallback: if the reputation object contained a DOM-* evidence
        # ID but domain_id() did not expose it, recover it from the
        # evidence harvested above.
        if (
            not rep_id
            and
            (
                not domain_is_official
                or
                malicious_domain
                or
                lookalike_domain
            )
        ):
            domain_fallback = first_evidence_with_prefix(
                "DOM-"
            )

            if domain_fallback:
                add_evidence(domain_fallback)

        # ----------------------------------------------------
        # 4. MESSAGE ID
        # ----------------------------------------------------

        # The message itself is the primary evidence record and should
        # remain present whenever it is a valid Arena evidence ID.
        add_evidence(message_id)

        # ----------------------------------------------------
        # 5. THREAD EVIDENCE
        # ----------------------------------------------------

        # Thread history is included when it materially contributed to
        # the detection, particularly multi-turn grooming.
        if grooming_signal:

            add_evidence(
                thread_id
            )

            # If the explicit thread_id was unavailable but the thread
            # investigation returned a THR-* evidence ID, recover it.
            if (
                thread_id
                not in ordered_evidence
            ):
                thread_fallback = first_evidence_with_prefix(
                    "THR-"
                )

                if thread_fallback:
                    add_evidence(
                        thread_fallback
                    )

        # ----------------------------------------------------
        # 6. POLICY / LOG EVIDENCE
        # ----------------------------------------------------

        # Policy and log IDs are only added when they are the strongest
        # remaining evidence for an escalation. We do not add them
        # routinely because extra unrelated IDs can hurt Evidence F1.
        if resolution == "escalate":

            policy_fallback = first_evidence_with_prefix(
                "POL-"
            )

            if policy_fallback:
                add_evidence(
                    policy_fallback
                )

            log_fallback = first_evidence_with_prefix(
                "LOG-"
            )

            if log_fallback:
                add_evidence(
                    log_fallback
                )

        # ----------------------------------------------------
        # FINAL LIMIT
        # ----------------------------------------------------

        ordered_evidence = ordered_evidence[:20]

        # ====================================================
        # UNCERTAINTIES
        # ====================================================

        uncertainties = []

        if not domain_is_official:

            uncertainties.append(
                "Sender domain is not an approved "
                "official internal domain."
            )

        if not sender_is_employee:

            uncertainties.append(
                "Sender was not verified as an "
                "internal employee."
            )

        if not authentication_ok:

            uncertainties.append(
                "SPF/DKIM/DMARC did not all pass."
            )

        if (
            injection_present
            and
            not genuine_injection
        ):

            uncertainties.append(
                "Instruction-like text appears to be "
                "quoted or reported rather than directed "
                "at the security agent."
            )

        # ====================================================
        # CUSTOMER RESPONSE
        # ====================================================

        evidence_text = ", ".join(
            ordered_evidence[:8]
        )

        if not evidence_text:

            evidence_text = (
                "retrieved investigation records"
            )

        if resolution == "allow":

            customer_response = (
                "The email was investigated and allowed "
                "because the available sender, domain, "
                "authentication, reputation, and content "
                "checks did not establish a clear threat. "
                f"Evidence: {evidence_text}."
            )

        elif resolution == "warn":

            customer_response = (
                "The email was investigated and delivered "
                "with an external-sender warning because "
                "the available evidence did not establish "
                "a definite malicious threat. "
                f"Evidence: {evidence_text}."
            )

        elif resolution == "quarantine":

            customer_response = (
                "The email was investigated and quarantined "
                f"because of {issue.replace('_', ' ')} "
                f"indicators. Evidence: {evidence_text}."
            )

        else:

            customer_response = (
                "The email was escalated to Tier-2 SOC "
                "because the investigation identified a "
                "complex security concern requiring human "
                f"review. Evidence: {evidence_text}."
            )

        # ====================================================
        # FINAL OUTPUT
        # ====================================================

        return {

            "task_id":
                task_id,

            "case_classification": {

                "category":
                    "cybersecurity_triage",

                "issue":
                    issue,

                "severity":
                    severity,
            },

            "decision": {

                "resolution":
                    resolution,

                "escalation_required":
                    escalation_required,
            },

            "evidence":
                ordered_evidence,

            "uncertainties":
                uncertainties,

            "customer_response":
                customer_response,

            "confidence":
                float(
                    max(
                        0.0,
                        min(
                            1.0,
                            confidence,
                        ),
                    )
                ),

            "prompt_injection_detected":
                bool(
                    genuine_injection
                ),
        }


# ============================================================
# MAIN.PY ENTRY POINT
# ============================================================

def solve(
    task,
    tools,
    **kwargs,
):

    _ = kwargs

    agent = Agent(
        tools
    )

    return agent.solve(
        task
    )