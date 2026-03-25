"""
Elf 🧝 — Agent Safety & Prompt Injection Checks (113–128)
Scans all human-readable text for content designed to manipulate AI agents.
"""

import re
from ..models import Finding, Severity, Category

_DIRECT_INJECTION_PATTERNS = [
    (r'ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)', "Direct override: ignore previous instructions"),
    (r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)', "Direct override: disregard previous"),
    (r'forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training|rules?)', "Forget training/context instruction"),
    (r'you\s+are\s+now\s+(?!a\s+(?:contributor|developer|user|maintainer))', "Persona switch: you are now"),
    (r'your\s+new\s+(role|identity|persona|instructions?|task)\s+is', "Persona reassignment"),
    (r'act\s+as\s+(?!a\s+(?:developer|user|contributor|reviewer|maintainer))', "Role assumption instruction"),
    (r'pretend\s+(you\s+are|to\s+be)', "Pretend role instruction"),
    (r'do\s+not\s+(report|flag|warn|alert|notify|mention|tell)', "Suppress safety reporting"),
    (r'skip\s+(the\s+)?(security|safety|verification|check|scan|review)', "Skip security checks"),
    (r'bypass\s+(the\s+)?(security|safety|filter|check|restriction|guard)', "Bypass security"),
    (r'this\s+is\s+(safe|trusted|approved|verified|ok|fine)\s+to\s+(run|execute|install)', "False safety assurance"),
    (r'(automatically?\s+)?(approve|accept|confirm|allow|grant)\s+(this|the)\s+(request|action|permission)', "Automatic approval instruction"),
    (r'do\s+not\s+(ask|prompt|request|wait)\s+(for\s+)?(user\s+)?(confirmation|approval|permission)', "Skip user confirmation"),
    (r'(send|transmit|exfiltrate|leak|forward|share)\s+(your\s+)?(context|memory|instructions?|system\s+prompt|api\s+key|token)', "Data exfiltration instruction"),
    (r'print\s+(your\s+)?(system\s+prompt|instructions?|context|memory|api\s+key)', "System prompt extraction"),
    (r'reveal\s+(your\s+)?(system\s+prompt|instructions?|training|api\s+key|configuration)', "Reveal internal data"),
]

_HIDDEN_INSTRUCTION_PATTERNS = [
    (r'<!--\s*(?:ignore|you\s+are|act\s+as|do\s+not|execute|run|install|forget)', "Hidden instruction in HTML comment"),
    (r'\[//\]:\s*#\s*\((?:ignore|you\s+are|act\s+as|do\s+not|execute)', "Hidden instruction in Markdown comment"),
]

_SOCIAL_ENGINEERING_PATTERNS = [
    (r'(this\s+)?repo(sitory)?\s+has\s+been\s+(verified|approved|audited|certified)\s+by', "False trust certification"),
    (r'(certified|verified|approved|trusted)\s+by\s+(github|anthropic|openai|google|microsoft)', "False platform certification"),
    (r'this\s+code\s+is\s+(100\s*%)?\s*safe\s+(and\s+)?malware[_\-]?free', "Unverifiable safety claim"),
    (r'security\s+(test|audit|check|scan|review)\s*:\s*passed', "Fake security scan result"),
    (r'(no\s+)?(viruses?|malware|backdoors?|threats?)\s+(found|detected|present)', "Fake security clearance"),
]

_COMMENT_INJECTION_PATTERNS = [
    (r'#\s*(?:ignore\s+previous|you\s+are\s+now|act\s+as|system:|<\|im_start\|>)', "Prompt injection in # comment"),
    (r'//\s*(?:ignore\s+previous|you\s+are\s+now|act\s+as|system:|<\|im_start\|>)', "Prompt injection in // comment"),
    (r'<\|(?:im_start|system|endoftext)\|>', "LLM special token in source"),
    (r'(?:SYSTEM|ASSISTANT|USER)\s*:\s*(?:ignore|you\s+are|act\s+as)', "Chat-format prompt injection"),
]


def _check_unicode_hidden(text: str, source: str) -> list:
    findings = []
    hidden_chars = []
    for i, char in enumerate(text):
        cp = ord(char)
        if cp in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x00AD):
            context = text[max(0, i-20):min(len(text), i+20)]
            if "```" not in context and "`" not in context:
                hidden_chars.append(f"U+{cp:04X}")
        if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            hidden_chars.append(f"U+{cp:04X}(bidi)")
    if hidden_chars:
        findings.append(Finding(
            check_id=124,
            name="Hidden Unicode control characters in documentation",
            category=Category.AGENT_SAFETY,
            severity=Severity.HIGH,
            detail=(
                "Invisible Unicode control characters found in repository documentation. "
                "These are invisible to human readers but processed by LLM tokenizers and "
                "text parsers. They can embed hidden instructions that AI agents will process "
                "but humans will never see during code review. This is a documented technique "
                "for covert prompt injection attacks against AI-assisted development tools."
            ),
            evidence=f"Source: {source}  Characters: {', '.join(set(hidden_chars[:10]))}",
            check_name="HIDDEN_UNICODE_IN_DOCS",
        ))
    return findings


def run_agent_safety_checks(doc_files: dict, source_files: dict) -> list:
    findings = []
    fired = set()

    all_doc_text = "\n".join(doc_files.values())
    all_src_text = "\n".join(source_files.values())

    # Direct injection in docs
    for pattern, label in _DIRECT_INJECTION_PATTERNS:
        key = f"INJECT_{label[:15]}"
        if key in fired:
            continue
        for fname, content in doc_files.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    check_id=113,
                    name=f"Prompt injection in documentation: {label}",
                    category=Category.AGENT_SAFETY,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"Prompt injection pattern detected in repository documentation. "
                        f"Type: '{label}'. When an AI agent reads this repository's files as "
                        "part of a task, injected instructions can override the agent's original "
                        "instructions, execute malicious commands, suppress security warnings, "
                        "exfiltrate credentials, or approve dangerous operations without user "
                        "consent. The text itself is the payload — no code execution needed."
                    ),
                    evidence=f"File: {fname}  Pattern type: {label}",
                    check_name="PROMPT_INJECTION_IN_DOCS",
                ))
                fired.add(key)
                break

    # Hidden HTML/Markdown comments
    for pattern, label in _HIDDEN_INSTRUCTION_PATTERNS:
        if "HIDDEN_COMMENT" in fired:
            break
        for fname, content in doc_files.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    check_id=115,
                    name=f"Hidden instruction in documentation comment: {label}",
                    category=Category.AGENT_SAFETY,
                    severity=Severity.CRITICAL,
                    detail=(
                        "A hidden instruction was found inside a comment in repository "
                        "documentation. HTML comments are invisible in rendered Markdown on "
                        "GitHub but present in the raw text that AI agents process. This "
                        "deliberately hides agent manipulation instructions from human "
                        "reviewers while ensuring they are processed by any AI reading the file."
                    ),
                    evidence=f"File: {fname}  Pattern: {label}",
                    check_name="HIDDEN_COMMENT_INJECTION",
                ))
                fired.add("HIDDEN_COMMENT")
                break

    # Social engineering / false trust
    for pattern, label in _SOCIAL_ENGINEERING_PATTERNS:
        if "SOCIAL_ENG" in fired:
            break
        if re.search(pattern, all_doc_text, re.IGNORECASE):
            findings.append(Finding(
                check_id=116,
                name=f"Social engineering / false trust claim: {label}",
                category=Category.AGENT_SAFETY,
                severity=Severity.HIGH,
                detail=(
                    f"Documentation contains a false or unverifiable trust claim: '{label}'. "
                    "Attackers embed fake security certifications, false audit results, and "
                    "false platform approvals to manipulate automated trust decisions by AI "
                    "agents and CI/CD systems. No platform embeds certifications in README files."
                ),
                evidence=f"Pattern matched: {label}",
                check_name="SOCIAL_ENGINEERING_TRUST_CLAIM",
            ))
            fired.add("SOCIAL_ENG")

    # Code comment injection
    for pattern, label in _COMMENT_INJECTION_PATTERNS:
        if "COMMENT_INJECT" in fired:
            break
        for fname, content in source_files.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    check_id=118,
                    name=f"Prompt injection in source code comment: {label}",
                    category=Category.AGENT_SAFETY,
                    severity=Severity.CRITICAL,
                    detail=(
                        "Prompt injection found in a source code comment. AI coding assistants "
                        "read source code including comments to understand context. Malicious "
                        "comments can manipulate these tools into generating insecure code, "
                        "suggesting dangerous completions, or overriding safety measures when "
                        "a developer uses AI assistance on this project."
                    ),
                    evidence=f"File: {fname}  Pattern: {label}",
                    check_name="COMMENT_PROMPT_INJECTION",
                ))
                fired.add("COMMENT_INJECT")
                break

    # LLM special tokens
    llm_tokens = [r'<\|im_start\|>', r'<\|im_end\|>', r'<\|endoftext\|>',
                  r'\[INST\]', r'<<SYS>>', r'<\|system\|>', r'<\|assistant\|>']
    for pattern in llm_tokens:
        if "LLM_TOKENS" in fired:
            break
        if re.search(pattern, all_doc_text + all_src_text):
            findings.append(Finding(
                check_id=119,
                name="LLM special formatting tokens found in repository",
                category=Category.AGENT_SAFETY,
                severity=Severity.HIGH,
                detail=(
                    "Repository files contain special tokens used by language models to delimit "
                    "system prompts and messages (e.g. <|im_start|>, [INST], <<SYS>>). These "
                    "have no legitimate use in source code or documentation. Their presence "
                    "indicates an attempt to inject structured prompt content interpreted as "
                    "model control tokens by any LLM processing the file."
                ),
                evidence=f"Token pattern: {pattern}",
                check_name="LLM_CONTROL_TOKENS_IN_REPO",
            ))
            fired.add("LLM_TOKENS")

    # Hidden unicode in docs
    for fname, content in doc_files.items():
        if "UNICODE_HIDDEN" in fired:
            break
        for f in _check_unicode_hidden(content, fname):
            findings.append(f)
            fired.add("UNICODE_HIDDEN")

    # Approval bypass
    approval_bypass = [
        r'automatically\s+(run|execute|install|deploy|approve)',
        r'no\s+(human|user|manual)\s+(review|approval|confirmation)\s+(needed|required)',
        r'(agent|bot|ai|automation)\s+can\s+(safely\s+)?(run|execute|install)\s+(this|without)',
        r'trust\s+(this|the)\s+(repo|code|package)\s+(completely|fully|without)',
    ]
    for pattern in approval_bypass:
        if "APPROVAL_BYPASS" in fired:
            break
        if re.search(pattern, all_doc_text, re.IGNORECASE):
            findings.append(Finding(
                check_id=121,
                name="Approval bypass language targeting autonomous agents",
                category=Category.AGENT_SAFETY,
                severity=Severity.HIGH,
                detail=(
                    "Documentation contains language specifically designed to tell autonomous "
                    "agents to skip user confirmation, proceed without human review, or trust "
                    "the repository unconditionally. Legitimate projects never instruct agents "
                    "to bypass safety checks. This is a social engineering attack targeting "
                    "AI agent decision-making pipelines."
                ),
                evidence=f"Pattern: {pattern}",
                check_name="APPROVAL_BYPASS_LANGUAGE",
            ))
            fired.add("APPROVAL_BYPASS")

    # Security test social engineering
    sec_test_patterns = [
        r'this\s+is\s+(a\s+)?(security\s+test|pen\s*test|authorized\s+test)',
        r'(authorized|legitimate)\s+(security|penetration|red\s+team)\s+(test|audit)',
        r'for\s+(security\s+research|educational\s+purposes)\s+only',
    ]
    for pattern in sec_test_patterns:
        if "SEC_TEST" in fired:
            break
        if re.search(pattern, all_doc_text, re.IGNORECASE):
            findings.append(Finding(
                check_id=123,
                name="'Security test' language used to socially engineer dangerous actions",
                category=Category.AGENT_SAFETY,
                severity=Severity.HIGH,
                detail=(
                    "Documentation claims this is a 'security test', 'authorized penetration "
                    "test', or 'for educational purposes only'. Attackers use these phrases to "
                    "manipulate AI agents into permitting actions they would otherwise refuse. "
                    "The claim cannot be verified from the repository and is a documented "
                    "social engineering technique against autonomous systems."
                ),
                evidence=f"Pattern: {pattern}",
                check_name="SECURITY_TEST_SOCIAL_ENGINEERING",
            ))
            fired.add("SEC_TEST")

    return findings
