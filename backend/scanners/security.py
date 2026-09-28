"""Security scanner for detecting security vulnerabilities."""

import re
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, Finding


class SecurityScanner(BaseScanner):
    """Scan for security vulnerabilities."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "security"

    def scan(self) -> List[Finding]:
        """Run all security checks."""
        self._check_hardcoded_secrets()
        self._check_sql_injection()
        self._check_command_injection()
        self._check_xss_vulnerabilities()
        self._check_weak_auth()
        self._check_missing_rate_limiting()
        self._check_unsafe_cors()
        self._check_debug_mode()
        self._check_sensitive_logging()
        self._check_insecure_defaults()
        return self.findings

    def _check_hardcoded_secrets(self):
        """Check for hardcoded API keys, passwords, tokens."""
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
            (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret Key"),
            (r'(?i)(access[_-]?token|accesstoken)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Access Token"),
            (r'(?i)(password|passwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),
            (r'(?i)(private[_-]?key|privatekey)\s*[=:]\s*["\']([^"\']{20,})["\']', "Private Key"),
            (r'(?i)(aws[_-]?access[_-]?key|awsaccesskey)\s*[=:]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
            (r'(?i)(aws[_-]?secret[_-]?key|awssecretkey)\s*[=:]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "AWS Secret Key"),
            (r'(?i)(github[_-]?token|githubtoken)\s*[=:]\s*["\'](gh[ps]_[a-zA-Z0-9]{36})["\']', "GitHub Token"),
            (r'(?i)(slack[_-]?token|slacktoken)\s*[=:]\s*["\'](xox[baprs]-[a-zA-Z0-9-]+)["\']', "Slack Token"),
            (r'(?i)(stripe[_-]?key|stripekey)\s*[=:]\s*["\'](sk_live_[a-zA-Z0-9]{24})["\']', "Stripe Secret Key"),
            (r'sk_live_[a-zA-Z0-9]{24}', "Stripe Secret Key (generic)"),
            (r'pk_live_[a-zA-Z0-9]{24}', "Stripe Publishable Key (generic)"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, secret_type in secret_patterns:
                for match in re.finditer(pattern, content, re.MULTILINE):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="critical",
                        title=f"Hardcoded {secret_type} Detected",
                        description=f"A potential {secret_type.lower()} appears to be hardcoded in the source code. This could expose sensitive credentials if the code is shared or committed to a repository.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="high",
                        recommendation=f"Move the {secret_type.lower()} to an environment variable or secret management system. Use a .env file for local development and ensure it's in .gitignore.",
                        metadata={"secret_type": secret_type}
                    ))

    def _check_sql_injection(self):
        """Check for potential SQL injection vulnerabilities."""
        # Patterns that suggest string concatenation in SQL queries
        sql_patterns = [
            (r'(?i)(execute|query|select|insert|update|delete)\s*\(\s*["\'].*%.*["\']', "String formatting in SQL"),
            (r'(?i)(execute|query|select|insert|update|delete)\s*\(\s*["\'].*\+.*["\']', "String concatenation in SQL"),
            (r'(?i)cursor\.execute\s*\(\s*f["\']', "F-string in SQL execute"),
            (r'(?i)\.execute\s*\(\s*%.*%', "Percent formatting in SQL"),
            (r'(?i)db\.execute\s*\(\s*["\'].*\{.*\}.*["\']', "Format string in SQL"),
        ]

        for file_path in self._get_source_files([".py", ".js", ".ts", ".go", ".java", ".php"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in sql_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Potential SQL Injection Risk: {desc}",
                        description=f"SQL query appears to be constructed using string concatenation or formatting, which could lead to SQL injection if user input is not properly sanitized.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Use parameterized queries (prepared statements) instead of string concatenation. For example, use cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)) instead of cursor.execute('SELECT * FROM users WHERE id = ' + user_id).",
                        metadata={"pattern_type": desc}
                    ))

    def _check_command_injection(self):
        """Check for potential command injection vulnerabilities."""
        cmd_patterns = [
            (r'(?i)(subprocess\.run|subprocess\.call|subprocess\.Popen|os\.system|os\.popen)\s*\(.*\+', "String concatenation in command"),
            (r'(?i)(subprocess\.run|subprocess\.call|subprocess\.Popen|os\.system|os\.popen)\s*\(.*f["\']', "F-string in command"),
            (r'(?i)shell=True', "Shell=True usage"),
            (r'(?i)exec\s*\(.*\+', "String concatenation in exec"),
            (r'(?i)eval\s*\(', "Eval usage"),
        ]

        for file_path in self._get_source_files([".py", ".js", ".ts", ".go", ".java", ".php"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in cmd_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Potential Command Injection Risk: {desc}",
                        description=f"Command execution appears to use user input without proper validation, which could lead to command injection.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Avoid shell=True, use subprocess with explicit argument lists, and validate/sanitize all user input before using in commands.",
                        metadata={"pattern_type": desc}
                    ))

    def _check_xss_vulnerabilities(self):
        """Check for potential XSS vulnerabilities."""
        xss_patterns = [
            (r'(?i)innerHTML\s*=.*\+', "innerHTML with concatenation"),
            (r'(?i)dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
            (r'(?i)v-html\s*=', "Vue v-html directive"),
            (r'(?i)\|safe', "Jinja2 safe filter"),
            (r'(?i)mark_safe\(', "Django mark_safe"),
            (r'(?i)autoescape\s*=\s*false', "Autoescape disabled"),
        ]

        for file_path in self._get_source_files([".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".jinja2", ".j2"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in xss_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="medium",
                        title=f"Potential XSS Risk: {desc}",
                        description=f"Code pattern detected that could lead to Cross-Site Scripting (XSS) if user input is not properly sanitized before rendering.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Ensure all user input is properly escaped before rendering. Use framework-provided escaping mechanisms (e.g., React's default escaping, Jinja2 autoescape, Django's template system).",
                        metadata={"pattern_type": desc}
                    ))

    def _check_weak_auth(self):
        """Check for weak authentication implementations."""
        auth_patterns = [
            (r'(?i)password\s*==\s*["\']', "Hardcoded password comparison"),
            (r'(?i)md5\s*\(', "MD5 hashing (weak)"),
            (r'(?i)sha1\s*\(', "SHA1 hashing (weak)"),
            (r'(?i)bcrypt\.hashpw\s*\([^)]*,\s*\d{1,2}\s*\)', "Low bcrypt rounds"),
            (r'(?i)jwt\.encode.*algorithm\s*=\s*["\']none["\']', "JWT 'none' algorithm"),
            (r'(?i)verify_exp\s*=\s*False', "JWT expiration verification disabled"),
        ]

        for file_path in self._get_source_files([".py", ".js", ".ts", ".go", ".java", ".php"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in auth_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    severity = "critical" if "none" in pattern or "verify_exp.*False" in pattern else "high"
                    if "md5" in pattern or "sha1" in pattern:
                        severity = "medium"

                    self._add_finding(Finding(
                        category=self.category,
                        severity=severity,
                        title=f"Weak Authentication: {desc}",
                        description=f"Authentication implementation uses weak or deprecated methods that could compromise user credentials or session security.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="high",
                        recommendation="Use strong, modern authentication practices: bcrypt/argon2 for password hashing (12+ rounds), RS256/ES256 for JWT signing, always verify token expiration, use constant-time comparison.",
                        metadata={"pattern_type": desc}
                    ))

    def _check_missing_rate_limiting(self):
        """Check for missing rate limiting on sensitive endpoints."""
        # Look for auth endpoints without rate limiting
        auth_endpoints = [
            r'(?i)(/login|/signin|/auth|/register|/signup|/password|/reset)',
            r'(?i)(@app\.(post|get)\s*\(\s*["\'].*(login|auth|register))',
        ]

        rate_limit_indicators = [
            "rate_limit", "ratelimit", "limiter", "slowapi", "flask-limiter",
            "express-rate-limit", "django-ratelimit", "fastapi-limiter"
        ]

        has_rate_limit = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for indicator in rate_limit_indicators:
                if indicator in content.lower():
                    has_rate_limit = True
                    break

        if not has_rate_limit:
            for file_path in self._get_source_files([".py", ".js", ".ts"]):
                content = self._read_file(file_path)
                if not content:
                    continue

                for pattern in auth_endpoints:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                        self._add_finding(Finding(
                            category=self.category,
                            severity="high",
                            title="Missing Rate Limiting on Authentication Endpoint",
                            description="Authentication endpoints (login, register, password reset) appear to lack rate limiting, making them vulnerable to brute-force and credential stuffing attacks.",
                            evidence=f"Line {line_num}: {line_content[:100]}",
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            confidence="medium",
                            recommendation="Implement rate limiting on all authentication endpoints. Use libraries like slowapi (FastAPI), flask-limiter (Flask), express-rate-limit (Express), or django-ratelimit (Django). Configure appropriate limits (e.g., 5 requests/minute for login).",
                            metadata={"endpoint_type": "auth"}
                        ))

    def _check_unsafe_cors(self):
        """Check for unsafe CORS configuration."""
        cors_patterns = [
            (r'(?i)allow_origin\s*=\s*["\']\*["\']', "CORS allows all origins (*)"),
            (r'(?i)cors\s*\(\s*\)', "CORS with default (permissive) settings"),
            (r'(?i)allow_credentials\s*=\s*True.*allow_origin\s*=\s*["\']\*["\']', "CORS allows credentials with wildcard origin"),
            (r'(?i)origin\s*:\s*["\']\*["\']', "CORS wildcard origin in config"),
        ]

        for file_path in self._get_source_files([".py", ".js", ".ts", ".go", ".java"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in cors_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="medium",
                        title=f"Unsafe CORS Configuration: {desc}",
                        description=f"CORS is configured in a way that may allow unauthorized cross-origin requests, potentially exposing sensitive data or enabling CSRF attacks.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="high",
                        recommendation="Restrict CORS to specific trusted origins. Avoid using wildcard (*) with credentials. Configure explicit allowed origins, methods, and headers.",
                        metadata={"pattern_type": desc}
                    ))

    def _check_debug_mode(self):
        """Check for debug mode enabled in production."""
        debug_patterns = [
            (r'(?i)debug\s*=\s*True', "Debug mode enabled"),
            (r'(?i)DEBUG\s*=\s*True', "DEBUG=True in config"),
            (r'(?i)app\.run\s*\(.*debug\s*=\s*True', "Flask debug mode"),
            (r'(?i)fastapi\.FastAPI\s*\(.*debug\s*=\s*True', "FastAPI debug mode"),
            (r'(?i)NODE_ENV\s*=\s*["\']development["\']', "NODE_ENV=development"),
            (r'(?i)spring\.profiles\.active\s*=\s*dev', "Spring dev profile"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in debug_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Debug Mode Enabled: {desc}",
                        description=f"Debug mode is enabled, which can expose sensitive information (stack traces, configuration, internal paths) in error responses.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="high",
                        recommendation="Disable debug mode in production. Use environment-specific configuration (e.g., DEBUG=False, NODE_ENV=production). Ensure production deployments use production settings.",
                        metadata={"pattern_type": desc}
                    ))

    def _check_sensitive_logging(self):
        """Check for sensitive information in logs."""
        logging_patterns = [
            (r'(?i)log.*(password|passwd|secret|token|api[_-]?key|credit[_-]?card|ssn|social[_-]?security)', "Sensitive data in log"),
            (r'(?i)print\s*\(.*(password|passwd|secret|token|api[_-]?key)', "Sensitive data in print"),
            (r'(?i)console\.(log|error|warn)\s*\(.*(password|passwd|secret|token|api[_-]?key)', "Sensitive data in console.log"),
            (r'(?i)logger\.(info|debug|error|warn)\s*\(.*(password|passwd|secret|token|api[_-]?key)', "Sensitive data in logger"),
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
                        title=f"Sensitive Information in Logs: {desc}",
                        description=f"Code appears to log sensitive information (passwords, tokens, API keys) which could be exposed in log files or monitoring systems.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Remove sensitive data from logs. Use structured logging with field filtering, or mask sensitive values before logging. Consider using a logging filter to automatically redact sensitive fields.",
                        metadata={"pattern_type": desc}
                    ))

    def _check_insecure_defaults(self):
        """Check for insecure default configurations."""
        insecure_patterns = [
            (r'(?i)ssl_verify\s*=\s*False', "SSL verification disabled"),
            (r'(?i)verify\s*=\s*False', "Certificate verification disabled"),
            (r'(?i)allow_insecure\s*=\s*True', "Insecure connections allowed"),
            (r'(?i)tls_config.*insecure', "TLS insecure config"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in insecure_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Insecure Default Configuration: {desc}",
                        description=f"Configuration disables security features like SSL/TLS verification, making the application vulnerable to man-in-the-middle attacks.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="high",
                        recommendation="Enable SSL/TLS verification in production. Use proper certificate validation. If using self-signed certificates in development, use a separate configuration that doesn't affect production.",
                        metadata={"pattern_type": desc}
                    ))