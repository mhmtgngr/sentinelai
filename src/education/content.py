"""Security education content library — maps alert categories to training material."""

from __future__ import annotations

from src.core.models import AlertCategory

# ── Education content per topic ──
# Each topic maps to an HTML block that gets included in the education email.

EDUCATION_CONTENT: dict[str, str] = {
    # ── Phishing ──
    "recognizing_phishing_emails": """
    <h3>How to Recognize Phishing Emails</h3>
    <ul>
        <li><strong>Check the sender:</strong> Look carefully at the email address, not just the display name. Attackers often use addresses that look similar to legitimate ones (e.g., <code>support@micros0ft.com</code>).</li>
        <li><strong>Urgency & fear:</strong> Phishing emails create artificial urgency — "Your account will be locked in 24 hours!" Legitimate organizations rarely threaten you via email.</li>
        <li><strong>Hover before clicking:</strong> Hover over links to see the actual URL. If it doesn't match the expected domain, don't click.</li>
        <li><strong>Attachments from strangers:</strong> Never open attachments from unknown senders. Even from known senders, verify if the attachment was expected.</li>
        <li><strong>Grammar & formatting:</strong> Many phishing emails contain spelling errors, unusual formatting, or inconsistent branding.</li>
    </ul>
    """,

    "safe_link_practices": """
    <h3>Safe Link Practices</h3>
    <ul>
        <li><strong>Hover first:</strong> Always hover over links to preview the destination URL before clicking.</li>
        <li><strong>Check for HTTPS:</strong> Ensure sensitive websites use HTTPS (look for the padlock icon).</li>
        <li><strong>Type it yourself:</strong> When in doubt, type the website address directly into your browser instead of clicking a link.</li>
        <li><strong>URL shorteners:</strong> Be cautious with shortened URLs (bit.ly, tinyurl). Use a URL expander tool if unsure.</li>
        <li><strong>QR codes:</strong> Treat QR codes like links — they can redirect to malicious sites. Preview the URL before proceeding.</li>
    </ul>
    """,

    "reporting_suspicious_emails": """
    <h3>How to Report Suspicious Emails</h3>
    <ul>
        <li><strong>Don't forward:</strong> Use your email client's "Report Phishing" button or forward as an attachment to your security team.</li>
        <li><strong>Don't reply:</strong> Never reply to a suspicious email, even to tell the sender it's a scam.</li>
        <li><strong>Report promptly:</strong> The sooner you report, the sooner the security team can protect others.</li>
        <li><strong>Already clicked?</strong> If you clicked a link or entered credentials, report it immediately and change your password.</li>
    </ul>
    """,

    # ── Malware ──
    "safe_download_practices": """
    <h3>Safe Download Practices</h3>
    <ul>
        <li><strong>Official sources only:</strong> Download software only from official websites or your organization's approved software catalog.</li>
        <li><strong>Verify installers:</strong> Check file hashes when available. Be suspicious of unexpected file extensions (.exe, .scr, .bat).</li>
        <li><strong>Avoid pirated software:</strong> Cracked software is a top malware distribution vector.</li>
        <li><strong>Browser extensions:</strong> Only install extensions from official stores and review their permissions.</li>
    </ul>
    """,

    "recognizing_malicious_attachments": """
    <h3>Recognizing Malicious Attachments</h3>
    <ul>
        <li><strong>Dangerous extensions:</strong> Be wary of <code>.exe</code>, <code>.scr</code>, <code>.bat</code>, <code>.ps1</code>, <code>.vbs</code>, <code>.js</code>, and macro-enabled Office files (<code>.docm</code>, <code>.xlsm</code>).</li>
        <li><strong>Double extensions:</strong> Files like <code>report.pdf.exe</code> are disguised executables.</li>
        <li><strong>Enable macros?</strong> If a document asks you to "Enable Macros" or "Enable Content", it's almost certainly malicious.</li>
        <li><strong>Password-protected archives:</strong> Attackers use password-protected ZIPs to bypass email scanners. Be extra cautious.</li>
    </ul>
    """,

    "endpoint_security_basics": """
    <h3>Endpoint Security Basics</h3>
    <ul>
        <li><strong>Keep updated:</strong> Always accept OS and application updates — they fix security vulnerabilities.</li>
        <li><strong>Antivirus active:</strong> Ensure your endpoint protection software is running and up to date.</li>
        <li><strong>Lock your screen:</strong> Press Win+L (Windows) or Ctrl+Cmd+Q (Mac) when stepping away.</li>
        <li><strong>Encrypt your drive:</strong> Enable BitLocker (Windows) or FileVault (Mac) for full-disk encryption.</li>
    </ul>
    """,

    # ── Brute Force / Credentials ──
    "strong_password_practices": """
    <h3>Strong Password Practices</h3>
    <ul>
        <li><strong>Length over complexity:</strong> A 16+ character passphrase is stronger than a short complex password. Example: <code>correct-horse-battery-staple</code>.</li>
        <li><strong>Unique per account:</strong> Never reuse passwords across services. A breach on one site compromises all accounts with the same password.</li>
        <li><strong>Password manager:</strong> Use an approved password manager to generate and store unique passwords.</li>
        <li><strong>Never share:</strong> IT will never ask for your password. Anyone who does is likely attempting a social engineering attack.</li>
    </ul>
    """,

    "multi_factor_authentication": """
    <h3>Multi-Factor Authentication (MFA)</h3>
    <ul>
        <li><strong>What is MFA?</strong> MFA adds a second verification step beyond your password — something you have (phone, key) or something you are (fingerprint).</li>
        <li><strong>Enable everywhere:</strong> Activate MFA on all accounts that support it, especially email, banking, and cloud services.</li>
        <li><strong>Authenticator apps &gt; SMS:</strong> Use an authenticator app (Microsoft Authenticator, Google Authenticator) instead of SMS when possible.</li>
        <li><strong>Watch for MFA fatigue:</strong> If you receive unexpected MFA prompts, do NOT approve them — report it to security immediately.</li>
        <li><strong>Hardware keys:</strong> For highest security, use FIDO2 hardware keys (YubiKey, etc.).</li>
    </ul>
    """,

    "account_security": """
    <h3>Account Security Best Practices</h3>
    <ul>
        <li><strong>Review sign-in activity:</strong> Periodically check your account's recent sign-in history for unfamiliar locations or devices.</li>
        <li><strong>Revoke unused apps:</strong> Review and remove third-party app permissions you no longer use.</li>
        <li><strong>Security alerts:</strong> Enable sign-in notifications so you're alerted when your account is accessed from a new device.</li>
    </ul>
    """,

    # ── Policy Violation ──
    "acceptable_use_policy": """
    <h3>Acceptable Use Policy Reminders</h3>
    <ul>
        <li><strong>Work devices:</strong> Company devices should be used primarily for business purposes.</li>
        <li><strong>Approved software:</strong> Only install software approved by IT. Unapproved tools can introduce vulnerabilities.</li>
        <li><strong>Cloud services:</strong> Use only sanctioned cloud services for storing company data. Avoid personal Dropbox, Google Drive, etc. for work files.</li>
        <li><strong>Network usage:</strong> Don't connect to untrusted Wi-Fi networks without using the company VPN.</li>
    </ul>
    """,

    "data_handling_guidelines": """
    <h3>Data Handling Guidelines</h3>
    <ul>
        <li><strong>Classify data:</strong> Understand what data is confidential, internal, or public. Handle each appropriately.</li>
        <li><strong>Encryption:</strong> Always encrypt sensitive data before transferring via email or external media.</li>
        <li><strong>Clean desk:</strong> Don't leave sensitive documents on your desk. Lock printed materials in drawers.</li>
        <li><strong>Disposal:</strong> Shred physical documents. Use secure deletion for digital files on removable media.</li>
    </ul>
    """,

    "compliance_requirements": """
    <h3>Compliance Requirements</h3>
    <ul>
        <li><strong>Regulations:</strong> Depending on your role, you may handle data governed by GDPR, HIPAA, PCI-DSS, or SOX. Know your obligations.</li>
        <li><strong>Data retention:</strong> Don't keep data longer than required. Follow your organization's retention schedule.</li>
        <li><strong>Incident reporting:</strong> Compliance incidents must be reported promptly — delayed reporting can result in regulatory penalties.</li>
    </ul>
    """,

    # ── Credential Compromise ──
    "password_hygiene": """
    <h3>Password Hygiene After a Compromise</h3>
    <ul>
        <li><strong>Change immediately:</strong> If your credentials were compromised, change your password on the affected account AND any account where you used the same password.</li>
        <li><strong>Check breach databases:</strong> Use <code>haveibeenpwned.com</code> to check if your email appears in known breaches.</li>
        <li><strong>Enable MFA:</strong> Add multi-factor authentication to prevent future unauthorized access even if credentials are stolen.</li>
        <li><strong>Monitor accounts:</strong> Watch for unusual activity on your accounts for the next several weeks.</li>
    </ul>
    """,

    "credential_reuse_risks": """
    <h3>The Danger of Credential Reuse</h3>
    <ul>
        <li><strong>Credential stuffing:</strong> Attackers take breached username/password pairs and automatically try them on hundreds of other services.</li>
        <li><strong>One breach = many breaches:</strong> If you reuse passwords, a breach on a low-security site can compromise your bank, email, and work accounts.</li>
        <li><strong>Solution:</strong> Use a password manager to generate unique, random passwords for every account.</li>
    </ul>
    """,

    # ── General ──
    "general_security_awareness": """
    <h3>General Security Awareness</h3>
    <ul>
        <li><strong>Think before you click:</strong> Pause and evaluate before clicking links, opening attachments, or providing information.</li>
        <li><strong>Report suspicious activity:</strong> If something seems off, report it. You are the first line of defense.</li>
        <li><strong>Keep software updated:</strong> Updates patch security vulnerabilities that attackers actively exploit.</li>
        <li><strong>Secure your workspace:</strong> Lock your computer, use strong passwords, and enable MFA wherever possible.</li>
        <li><strong>Social engineering:</strong> Be wary of unsolicited calls, emails, or messages asking for sensitive information — even if they appear to come from a colleague or executive.</li>
    </ul>
    """,
}


def get_education_html(topics: list[str]) -> str:
    """Compile education HTML for the given topic list."""
    sections = []
    for topic in topics:
        content = EDUCATION_CONTENT.get(topic)
        if content:
            sections.append(content.strip())
        else:
            sections.append(
                f"<h3>{topic.replace('_', ' ').title()}</h3>"
                "<p>Please contact your security team for more information on this topic.</p>"
            )
    return "\n<hr>\n".join(sections)


def get_category_topics(category: AlertCategory) -> list[str]:
    """Return relevant education topics for an alert category."""
    mapping: dict[AlertCategory, list[str]] = {
        AlertCategory.PHISHING: [
            "recognizing_phishing_emails",
            "safe_link_practices",
            "reporting_suspicious_emails",
        ],
        AlertCategory.MALWARE: [
            "safe_download_practices",
            "recognizing_malicious_attachments",
            "endpoint_security_basics",
        ],
        AlertCategory.BRUTE_FORCE: [
            "strong_password_practices",
            "multi_factor_authentication",
            "account_security",
        ],
        AlertCategory.POLICY_VIOLATION: [
            "acceptable_use_policy",
            "data_handling_guidelines",
            "compliance_requirements",
        ],
        AlertCategory.CREDENTIAL_COMPROMISE: [
            "password_hygiene",
            "credential_reuse_risks",
            "multi_factor_authentication",
        ],
        AlertCategory.DATA_EXFILTRATION: [
            "data_handling_guidelines",
            "acceptable_use_policy",
        ],
        AlertCategory.UNAUTHORIZED_ACCESS: [
            "account_security",
            "multi_factor_authentication",
        ],
        AlertCategory.RANSOMWARE: [
            "recognizing_malicious_attachments",
            "safe_download_practices",
            "endpoint_security_basics",
        ],
        AlertCategory.INSIDER_THREAT: [
            "acceptable_use_policy",
            "data_handling_guidelines",
        ],
    }
    return mapping.get(category, ["general_security_awareness"])
