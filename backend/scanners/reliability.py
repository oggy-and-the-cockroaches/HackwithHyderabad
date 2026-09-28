"""Reliability/UX scanner for detecting user experience and reliability issues."""

import re
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, Finding


class ReliabilityScanner(BaseScanner):
    """Scan for reliability and UX issues."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "reliability"

    def scan(self) -> List[Finding]:
        """Run all reliability/UX checks."""
        self._check_missing_404()
        self._check_unsafe_error_messages()
        self._check_stack_trace_exposure()
        self._check_broken_links()
        self._check_missing_input_validation()
        self._check_poor_api_errors()
        self._check_missing_health_check()
        return self.findings

    def _check_missing_404(self):
        """Check for missing 404 handling."""
        # Check for custom 404 pages/handlers
        not_found_indicators = [
            r'(?i)404',
            r'(?i)not[_-]?found',
            r'(?i)page[_-]?not[_-]?found',
        ]

        has_404_handler = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for pattern in not_found_indicators:
                if re.search(pattern, content):
                    has_404_handler = True
                    break

        # For frontend projects, check for 404.html or 404.tsx/jsx
        frontend_404_files = ["404.html", "404.tsx", "404.jsx", "404.vue", "404.js", "404.ts",
                              "pages/404.tsx", "pages/404.jsx", "src/pages/404.tsx",
                              "app/404.tsx", "app/404.jsx"]
        for f in frontend_404_files:
            if (self.project_root / f).exists():
                has_404_handler = True
                break

        project_type = self.project_context.get("project_type", "unknown")
        if project_type in ["frontend", "fullstack"] and not has_404_handler:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Custom 404 Page Not Detected",
                description="No custom 404 (Not Found) page or handler was detected. Users who navigate to non-existent pages will see a generic browser or server error page, which provides a poor user experience.",
                evidence="No 404.html, 404.tsx, 404.jsx, or similar files found. No 404 handler detected in source code.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Create a user-friendly 404 page that matches your site design. Include a clear message, search functionality, and links to main sections. For SPAs, ensure your router handles unknown routes and shows the 404 page.",
                metadata={"check_type": "missing_404", "project_type": project_type}
            ))

    def _check_unsafe_error_messages(self):
        """Check for unsafe error messages that expose internal details."""
        unsafe_error_patterns = [
            (r'(?i)traceback\s*\(most recent call last\)', "Python traceback exposure"),
            (r'(?i)stack trace', "Stack trace exposure"),
            (r'(?i)at\s+[\w.]+\s*\(.*\.py:\d+\)', "Python stack trace line"),
            (r'(?i)file\s+".*\.py",\s*line\s+\d+', "Python file/line exposure"),
            (r'(?i)error.*sql.*syntax', "SQL error exposure"),
            (r'(?i)syntax error.*near', "SQL syntax error exposure"),
            (r'(?i)column.*does not exist', "Database schema exposure"),
            (r'(?i)table.*does not exist', "Database schema exposure"),
            (r'(?i)no such file or directory', "File system exposure"),
            (r'(?i)permission denied', "Permission exposure"),
            (r'(?i)connection refused', "Internal service exposure"),
            (r'(?i)ec2-\d+-\d+-\d+-\d+', "AWS internal hostname exposure"),
            (r'(?i)127\.0\.0\.1', "Localhost exposure in errors"),
            (r'(?i)localhost', "Localhost exposure in errors"),
        ]

        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in unsafe_error_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    self._add_finding(Finding(
                        category=self.category,
                        severity="high",
                        title=f"Potential Internal Detail Exposure in Errors: {desc}",
                        description=f"Error handling may expose internal implementation details (stack traces, file paths, database schema, internal hostnames) which could aid attackers in reconnaissance.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="medium",
                        recommendation="Implement generic error pages for production. Catch exceptions and return user-friendly messages without internal details. Log detailed errors server-side for debugging. Use framework error handling middleware (FastAPI HTTPException, Express error middleware, Flask error handlers).",
                        metadata={"pattern_type": desc, "check_type": "error_exposure"}
                    ))

    def _check_stack_trace_exposure(self):
        """Check for stack trace exposure in API responses."""
        # This is similar to unsafe_error_messages but focused on API responses
        pass  # Covered by _check_unsafe_error_messages

    def _check_broken_links(self):
        """Check for potentially broken internal links."""
        # This is hard to do statically without running the app
        # We'll check for common patterns that suggest broken links
        link_patterns = [
            (r'href\s*=\s*["\'](#|javascript:void\(0\))["\']', "Empty or javascript void links"),
            (r'href\s*=\s*["\']\s*["\']', "Empty href"),
            (r'(?i)href\s*=\s*["\']https?://localhost', "Localhost links in production code"),
            (r'(?i)href\s*=\s*["\']https?://127\.0\.0\.1', "127.0.0.1 links in production code"),
        ]

        for file_path in self._get_source_files([".html", ".jsx", ".tsx", ".vue", ".py", ".js", ".ts"]):
            content = self._read_file(file_path)
            if not content:
                continue

            for pattern, desc in link_patterns:
                for match in re.finditer(pattern, content):
                    line_num = content[:match.start()].count('\n') + 1
                    line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                    severity = "medium" if "localhost" in pattern or "127.0.0.1" in pattern else "low"

                    self._add_finding(Finding(
                        category=self.category,
                        severity=severity,
                        title=f"Potential Broken Link: {desc}",
                        description=f"Link pattern detected that may result in broken navigation or expose development URLs in production.",
                        evidence=f"Line {line_num}: {line_content[:100]}",
                        file_path=str(file_path.relative_to(self.project_root)),
                        line_number=line_num,
                        confidence="low",
                        recommendation="Review all links in templates and components. Replace placeholder links with actual routes. Use environment-specific configuration for API base URLs. Implement link checking in CI/CD.",
                        metadata={"pattern_type": desc, "check_type": "broken_links"}
                    ))

    def _check_missing_input_validation(self):
        """Check for missing input validation."""
        validation_patterns = [
            (r'(?i)request\.(form|json|args|query|params)\[', "Direct request data access"),
            (r'(?i)req\.(body|params|query|body)\[', "Direct Express request access"),
            (r'(?i)\$\_POST\[|\$\_GET\[|\$\_REQUEST\[', "Direct PHP superglobal access"),
            (r'(?i)request\.get_json\s*\(\s*\)', "Flask get_json without validation"),
        ]

        validation_libraries = [
            "pydantic", "marshmallow", "cerberus", "voluptuous", "jsonschema",
            "joi", "yup", "zod", "validator", "express-validator",
            "flask-wtf", "wtforms", "django-forms", "class-validator",
        ]

        has_validation = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for lib in validation_libraries:
                if lib in content.lower():
                    has_validation = True
                    break

        if not has_validation:
            for file_path in self._get_source_files([".py", ".js", ".ts"]):
                content = self._read_file(file_path)
                if not content:
                    continue

                for pattern, desc in validation_patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                        self._add_finding(Finding(
                            category=self.category,
                            severity="medium",
                            title=f"Potential Missing Input Validation: {desc}",
                            description=f"User input appears to be accessed directly without visible validation. This could lead to injection attacks, data corruption, or unexpected behavior.",
                            evidence=f"Line {line_num}: {line_content[:100]}",
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            confidence="low",
                            recommendation="Implement input validation for all user-supplied data. Use validation libraries (Pydantic, Zod, Joi, express-validator, etc.). Validate at the API boundary before processing. Define schemas for request bodies, query parameters, and path parameters.",
                            metadata={"pattern_type": desc, "check_type": "missing_validation"}
                        ))

    def _check_poor_api_errors(self):
        """Check for poor API error handling."""
        api_error_patterns = [
            (r'(?i)return\s+\{\s*["\']error["\']\s*:', "Basic error response"),
            (r'(?i)res\.status\(\d+\)\.send\(', "Express basic error"),
            (r'(?i)jsonify\s*\(\s*\{\s*["\']error["\']', "Flask basic error"),
            (r'(?i)HTTPException\s*\(', "FastAPI HTTPException"),
        ]

        structured_error_indicators = [
            "error_code", "error_code", "details", "timestamp", "request_id",
            "trace_id", "correlation_id", "status_code", "message", "errors"
        ]

        has_structured_errors = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for indicator in structured_error_indicators:
                if indicator in content.lower():
                    has_structured_errors = True
                    break

        if not has_structured_errors:
            for file_path in self._get_source_files([".py", ".js", ".ts"]):
                content = self._read_file(file_path)
                if not content:
                    continue

                for pattern, desc in api_error_patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""

                        self._add_finding(Finding(
                            category=self.category,
                            severity="low",
                            title=f"Potentially Unstructured API Error: {desc}",
                            description=f"API error responses may lack consistent structure (error codes, timestamps, request IDs, detailed messages), making it difficult for clients to handle errors programmatically.",
                            evidence=f"Line {line_num}: {line_content[:100]}",
                            file_path=str(file_path.relative_to(self.project_root)),
                            line_number=line_num,
                            confidence="low",
                            recommendation="Implement consistent API error response format with: error code, human-readable message, timestamp, request ID, and optional details. Use RFC 7807 (Problem Details for HTTP APIs) or similar standard. Include error codes that clients can programmatically handle.",
                            metadata={"pattern_type": desc, "check_type": "api_errors"}
                        ))

    def _check_missing_health_check(self):
        """Check for missing health check endpoint."""
        health_indicators = [
            r'(?i)/health',
            r'(?i)/healthz',
            r'(?i)/ready',
            r'(?i)/live',
            r'(?i)healthcheck',
            r'(?i)health_check',
        ]

        has_health = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for pattern in health_indicators:
                if re.search(pattern, content):
                    has_health = True
                    break

        if not has_health:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Health Check Endpoint Not Detected",
                description="No health check endpoint (/health, /healthz, /ready, /live) was detected. Health checks are essential for load balancers, container orchestration (Kubernetes), and monitoring systems to determine if the application is healthy.",
                evidence="No /health, /healthz, /ready, /live routes or healthcheck functions found in source code.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Implement a health check endpoint that returns 200 OK when the application is healthy. Include checks for: database connectivity, external service dependencies, disk space, memory. For Kubernetes, implement separate /live (liveness) and /ready (readiness) endpoints.",
                metadata={"check_type": "missing_health_check"}
            ))