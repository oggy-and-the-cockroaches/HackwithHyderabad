"""Privacy scanner for detecting privacy compliance issues."""

import re
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, Finding


class PrivacyScanner(BaseScanner):
    """Scan for privacy and compliance issues."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "privacy"

    def scan(self) -> List[Finding]:
        """Run all privacy checks."""
        self._check_missing_privacy_policy()
        self._check_missing_terms()
        self._check_missing_cookie_consent()
        self._check_data_collection()
        self._check_sensitive_data_storage()
        self._check_sensitive_data_logging()
        self._check_user_data_controls()
        self._check_contact_info()
        return self.findings

    def _check_missing_privacy_policy(self):
        """Check for missing privacy policy."""
        policy_files = [
            "privacy.html", "privacy.md", "privacy.txt", "privacy-policy.html",
            "privacy_policy.html", "privacy-policy.md", "PRIVACY.md", "PRIVACY.html",
            "legal/privacy.html", "legal/privacy.md", "docs/privacy.md"
        ]

        has_policy = False
        for policy_file in policy_files:
            if (self.project_root / policy_file).exists():
                has_policy = True
                break

        # Also check for privacy policy in common routes
        for file_path in self._get_source_files([".py", ".js", ".ts", ".jsx", ".tsx"]):
            content = self._read_file(file_path)
            if not content:
                continue
            if re.search(r'(?i)(privacy[_-]?policy|/privacy)', content):
                has_policy = True
                break

        if not has_policy:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Privacy Policy Appears to Be Missing",
                description="No privacy policy file or route was detected. Most jurisdictions require a privacy policy if you collect any personal data.",
                evidence="No privacy.html, privacy.md, privacy-policy.html, or similar files found. No /privacy route detected in source code.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Create a privacy policy that discloses what data you collect, how it's used, who it's shared with, and user rights. Place it at /privacy or link it from your footer. Consult legal requirements for your jurisdiction (GDPR, CCPA, etc.).",
                metadata={"check_type": "missing_privacy_policy"}
            ))

    def _check_missing_terms(self):
        """Check for missing terms of service/terms and conditions."""
        terms_files = [
            "terms.html", "terms.md", "terms.txt", "terms-of-service.html",
            "terms_of_service.html", "terms-and-conditions.html", "TERMS.md", "TERMS.html",
            "legal/terms.html", "legal/terms.md", "docs/terms.md"
        ]

        has_terms = False
        for terms_file in terms_files:
            if (self.project_root / terms_file).exists():
                has_terms = True
                break

        # Also check for terms in routes
        for file_path in self._get_source_files([".py", ".js", ".ts", ".jsx", ".tsx"]):
            content = self._read_file(file_path)
            if not content:
                continue
            if re.search(r'(?i)(terms[_-]?of[_-]?service|/terms|/tos)', content):
                has_terms = True
                break

        if not has_terms:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Terms of Service/Terms and Conditions Appear to Be Missing",
                description="No terms of service file or route was detected. Terms define the legal agreement between you and your users.",
                evidence="No terms.html, terms.md, terms-of-service.html, or similar files found. No /terms or /tos route detected in source code.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Create terms of service that define user obligations, intellectual property, liability limitations, and dispute resolution. Place it at /terms or link it from your footer. Consult legal requirements for your jurisdiction.",
                metadata={"check_type": "missing_terms"}
            ))

    def _check_missing_cookie_consent(self):
        """Check for missing cookie consent handling."""
        cookie_indicators = [
            "cookie", "consent", "gdpr", "cookieconsent", "cookie-consent",
            "cookie_banner", "cookie-banner", "cookie_notice", "cookie-notice"
        ]

        has_cookie_consent = False
        uses_cookies = False

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            content_lower = content.lower()
            for indicator in cookie_indicators:
                if indicator in content_lower:
                    has_cookie_consent = True
                    break

            # Check for cookie usage
            if re.search(r'(?i)(document\.cookie|cookie\s*=|set-cookie|cookies\[)', content):
                uses_cookies = True

        if uses_cookies and not has_cookie_consent:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Cookie Usage Detected Without Consent Mechanism",
                description="The application appears to use cookies but no cookie consent mechanism was detected. Many jurisdictions (GDPR, ePrivacy Directive) require consent for non-essential cookies.",
                evidence="Cookie usage detected in source code (document.cookie, set-cookie headers, etc.) but no cookie consent banner or consent management code found.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Implement a cookie consent banner for non-essential cookies. Use libraries like cookieconsent, osano, or custom implementation. Categorize cookies (necessary, analytics, marketing) and only set non-essential cookies after consent.",
                metadata={"check_type": "missing_cookie_consent"}
            ))

    def _check_data_collection(self):
        """Check for personal data collection indicators."""
        data_collection_patterns = [
            (r'(?i)(email|e-mail|mail)\s*[=:]\s*["\']?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']?', "Email collection"),
            (r'(?i)(name|full_name|first_name|last_name)\s*[=:]\s*["\']', "Name collection"),
            (r'(?i)(phone|telephone|mobile)\s*[=:]\s*["\']', "Phone collection"),
            (r'(?i)(address|street|city|zip|postal)\s*[=:]\s*["\']', "Address collection"),
            (r'(?i)(dob|date_of_birth|birthdate)\s*[=:]\s*["\']', "Date of birth collection"),
            (r'(?i)(ssn|social_security|national_id)\s*[=:]\s*["\']', "SSN/National ID collection"),
            (r'(?i)(credit_card|card_number|cvv|expiry)', "Credit card collection"),
            (r'(?i)(ip_address|ip|location|geolocation)', "IP/Location collection"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in data_collection_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="info",
                        title=f"Personal Data Collection Detected: {desc}",
                        description=f"Code appears to collect or process {desc.lower()}. Ensure this is disclosed in your privacy policy and you have a lawful basis for processing.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="low",
                        recommendation="Document this data collection in your privacy policy. Ensure you have a lawful basis (consent, contract, legitimate interest) for each type of personal data collected. Implement data minimization - only collect what you need.",
                        metadata={"data_type": desc, "check_type": "data_collection"}
                    ))

    def _check_sensitive_data_storage(self):
        """Check for sensitive data storage patterns."""
        sensitive_storage_patterns = [
            (r'(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*["\'][^"\']{8,}["\']', "Secrets in code/config"),
            (r'(?i)(credit_card|card_number|cvv|ssn|social_security)\s*[=:]\s*["\']', "Sensitive data in variables"),
            (r'(?i)INSERT\s+INTO.*(password|ssn|credit_card|card_number)', "Sensitive data in SQL"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in sensitive_storage_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Sensitive Data Storage Risk: {desc}",
                        description=f"Code appears to store sensitive personal data in a way that may not be properly protected (encryption, hashing, access controls).",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Ensure sensitive data is encrypted at rest. Use proper hashing for passwords (bcrypt/argon2). Never store credit card data - use PCI-compliant payment processors. Implement field-level encryption for PII.",
                        metadata={"data_type": desc, "check_type": "sensitive_storage"}
                    ))

    def _check_sensitive_data_logging(self):
        """Check for sensitive data in logging."""
        # This overlaps with security scanner but focuses on privacy aspect
        logging_patterns = [
            (r'(?i)log.*(email|phone|address|ssn|credit_card|dob|date_of_birth)', "PII in logs"),
            (r'(?i)print\s*\(.*(email|phone|address|ssn|credit_card|dob)', "PII in print"),
            (r'(?i)console\.(log|error|warn)\s*\(.*(email|phone|address|ssn|credit_card|dob)', "PII in console"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in logging_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="medium",
                        title=f"Personal Data in Logs: {desc}",
                        description=f"Personal identifiable information (PII) appears to be logged, which could violate privacy regulations and expose user data in log systems.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Remove PII from logs. Implement log filtering/redaction for sensitive fields. Use structured logging with explicit field allowlists. Consider pseudonymization in logs.",
                        metadata={"data_type": desc, "check_type": "pii_in_logs"}
                    ))

    def _check_user_data_controls(self):
        """Check for user data control mechanisms (deletion, export, access)."""
        control_patterns = [
            (r'(?i)(delete[_-]?account|account[_-]?deletion|right[_-]?to[_-]?be[_-]?forgotten)', "Account deletion"),
            (r'(?i)(data[_-]?export|export[_-]?data|data[_-]?portability)', "Data export"),
            (r'(?i)(data[_-]?access|access[_-]?my[_-]?data|subject[_-]?access)', "Data access"),
            (r'(?i)(gdpr|ccpa|privacy[_-]?rights)', "Privacy rights"),
        ]

        found_controls = []
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in control_patterns:
                if re.search(pattern, content):
                    found_controls.append(desc)

        # Check if project has user accounts/auth but no data controls
        has_auth = any(auth in self.project_context.get("auth_systems", []) for auth in ["jwt", "oauth", "session", "api_key"])
        if has_auth and not found_controls:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="User Account System Without Data Control Mechanisms",
                description="The application appears to have user authentication but no detectable mechanisms for users to delete their account, export their data, or access their personal data - rights required by GDPR, CCPA, and other regulations.",
                evidence=f"Authentication system detected: {', '.join(self.project_context.get('auth_systems', []))}. No account deletion, data export, or data access endpoints found.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Implement user data rights endpoints: account deletion (/account/delete), data export (/account/export), data access (/account/data). Ensure these are authenticated and follow privacy regulation requirements (30-day response for GDPR, 45-day for CCPA).",
                metadata={"check_type": "missing_user_controls", "auth_systems": self.project_context.get("auth_systems", [])}
            ))

    def _check_contact_info(self):
        """Check for privacy contact information."""
        contact_patterns = [
            r'(?i)(privacy[_-]?contact|privacy[_-]?email|dpo[_-]?email|data[_-]?protection[_-]?officer)',
            r'(?i)(privacy@|dpo@|gdpr@)',
        ]

        has_contact = False
        for file_path in self._get_source_files([".html", ".md", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx"]):
            content = self._read_file(file_path)
            if not content:
                continue
            for pattern in contact_patterns:
                if re.search(pattern, content):
                    has_contact = True
                    break

        if not has_contact:
            self._add_finding(Finding(
                category=self.category,
                severity="low",
                title="Privacy Contact Information Not Found",
                description="No privacy contact email or Data Protection Officer (DPO) contact information was detected. GDPR and other regulations require providing a way for users to contact you about privacy concerns.",
                evidence="No privacy@, dpo@, gdpr@ email addresses or privacy contact references found in source code or documentation.",
                file_path=None,
                line_number=None,
                confidence="low",
                recommendation="Add a privacy contact email (e.g., privacy@yourdomain.com) to your privacy policy and website footer. If required by GDPR (large scale processing, special categories), appoint a Data Protection Officer and publish their contact details.",
                metadata={"check_type": "missing_privacy_contact"}
            ))