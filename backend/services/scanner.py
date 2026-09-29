"""Scanner service that orchestrates all scanners."""

import os
import uuid
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from scanners.security import SecurityScanner
from scanners.privacy import PrivacyScanner
from scanners.reliability import ReliabilityScanner
from scanners.production import ProductionScanner
from scanners.base import Finding
from services.project_detector import detect_project
from services.hindsight import HindsightService
from services.llm import get_llm
from database.schema import get_db


class ScannerService:
    """Orchestrates all scanners and manages the scan process."""

    def __init__(self, project_root: str, project_id: str, scan_id: str):
        self.project_root = Path(project_root)
        self.project_id = project_id
        self.scan_id = scan_id
        self.project_context: Dict[str, Any] = {}
        self.all_findings: List[Finding] = []
        self.hindsight = HindsightService()

    async def run_scan(self, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Run the complete scan pipeline."""
        # Step 1: Detect project technologies
        if progress_callback:
            await progress_callback("Analyzing project structure", 10)
        self.project_context = detect_project(str(self.project_root))
        self.project_context["project_id"] = self.project_id

        # Step 2: Run static scanners
        if progress_callback:
            await progress_callback("Running security checks", 25)
        security_findings = SecurityScanner(str(self.project_root), self.project_context).scan()
        self.all_findings.extend(security_findings)

        if progress_callback:
            await progress_callback("Running privacy checks", 40)
        privacy_findings = PrivacyScanner(str(self.project_root), self.project_context).scan()
        self.all_findings.extend(privacy_findings)

        if progress_callback:
            await progress_callback("Running reliability checks", 55)
        reliability_findings = ReliabilityScanner(str(self.project_root), self.project_context).scan()
        self.all_findings.extend(reliability_findings)

        if progress_callback:
            await progress_callback("Running production readiness checks", 70)
        production_findings = ProductionScanner(str(self.project_root), self.project_context).scan()
        self.all_findings.extend(production_findings)

        # Step 3: Run runtime scanner (optional)
        if progress_callback:
            await progress_callback("Running runtime analysis", 80)
        runtime_findings = await self._run_runtime_scan()
        self.all_findings.extend(runtime_findings)

        # Step 4: AI reasoning
        if progress_callback:
            await progress_callback("Running AI reasoning", 90)
        ai_report = await self._run_ai_reasoning()

        # Step 5: Update Hindsight memory
        if progress_callback:
            await progress_callback("Updating Hindsight memory", 95)
        comparison = self.hindsight.compare_scans(self.project_id, self.scan_id, self.all_findings)
        self.hindsight.save_scan_results(self.project_id, self.scan_id, self.project_context, self.all_findings)

        # Step 6: Generate final report
        if progress_callback:
            await progress_callback("Generating report", 100)
        report = self._generate_report(ai_report, comparison)

        return report

    async def _run_runtime_scan(self) -> List[Finding]:
        """Run runtime analysis if possible."""
        # For MVP, we'll do a basic check for Docker and try to run it
        # This is a simplified version - full implementation would be more complex
        findings = []

        # Check if Dockerfile exists
        dockerfile = self.project_root / "Dockerfile"
        if dockerfile.exists():
            # Try to build and run with Docker
            try:
                runtime_findings = await self._run_docker_runtime_check()
                findings.extend(runtime_findings)
            except Exception as e:
                findings.append(Finding(
                    category="runtime",
                    severity="info",
                    title="Runtime Scan Skipped",
                    description=f"Dockerfile found but runtime scan could not be completed: {str(e)}",
                    evidence=f"Dockerfile exists at {dockerfile}",
                    file_path="Dockerfile",
                    confidence="low",
                    recommendation="Ensure Docker is installed and the Dockerfile builds successfully. The runtime scanner will provide additional checks for 404 behavior, security headers, and API error handling.",
                    metadata={"error": str(e)}
                ))

        return findings

    async def _run_docker_runtime_check(self) -> List[Finding]:
        """Run the application in Docker and perform runtime checks."""
        import subprocess
        import tempfile
        import time
        import httpx

        findings = []

        # Build Docker image
        image_tag = f"shipcheck-scan-{self.scan_id[:8]}"
        build_result = subprocess.run(
            ["docker", "build", "-t", image_tag, str(self.project_root)],
            capture_output=True, text=True, timeout=120
        )

        if build_result.returncode != 0:
            findings.append(Finding(
                category="runtime",
                severity="medium",
                title="Docker Build Failed",
                description="The Dockerfile exists but failed to build. This indicates potential issues with the Docker configuration that would prevent deployment.",
                evidence=f"Build error: {build_result.stderr[:500]}",
                file_path="Dockerfile",
                confidence="high",
                recommendation="Fix the Dockerfile build errors. Check the Dockerfile syntax, base image availability, and build context.",
                metadata={"build_error": build_result.stderr}
            ))
            return findings

        # Try to run the container and detect port
        container = None
        try:
            # Start container in background
            container = subprocess.Popen(
                ["docker", "run", "-d", "-P", image_tag],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            stdout, stderr = container.communicate(timeout=30)
            container_id = stdout.strip()

            if not container_id:
                raise Exception("Failed to start container")

            # Get mapped port
            port_result = subprocess.run(
                ["docker", "port", container_id],
                capture_output=True, text=True, timeout=10
            )

            port_mapping = port_result.stdout.strip()
            # Parse port (format: 80/tcp -> 0.0.0.0:32768)
            host_port = None
            for line in port_mapping.split('\n'):
                if '->' in line:
                    parts = line.split('->')
                    if len(parts) == 2:
                        host_port = parts[1].split(':')[-1]
                        break

            if not host_port:
                raise Exception("Could not determine mapped port")

            # Wait for app to start
            await asyncio.sleep(3)

            # Run runtime checks
            base_url = f"http://localhost:{host_port}"
            runtime_findings = await self._check_runtime_endpoints(base_url)
            findings.extend(runtime_findings)

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                category="runtime",
                severity="info",
                title="Docker Container Start Timeout",
                description="Container took too long to start. Application may have slow startup or health check issues.",
                evidence="Container start timeout after 30 seconds",
                confidence="medium",
                recommendation="Optimize application startup time. Add a health check endpoint that responds quickly.",
                metadata={}
            ))
        except Exception as e:
            findings.append(Finding(
                category="runtime",
                severity="info",
                title="Runtime Scan Error",
                description=f"Error during runtime analysis: {str(e)}",
                evidence=str(e),
                confidence="low",
                recommendation="Ensure the application starts correctly in Docker and exposes a port.",
                metadata={"error": str(e)}
            ))
        finally:
            # Cleanup
            if container:
                try:
                    subprocess.run(["docker", "stop", container_id], capture_output=True, timeout=10)
                    subprocess.run(["docker", "rm", container_id], capture_output=True, timeout=10)
                except Exception:
                    pass
            try:
                subprocess.run(["docker", "rmi", image_tag], capture_output=True, timeout=10)
            except Exception:
                pass

        return findings

    async def _check_runtime_endpoints(self, base_url: str) -> List[Finding]:
        """Check running application endpoints."""
        import httpx

        findings = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Check 404 behavior
            try:
                resp = await client.get(f"{base_url}/this-route-definitely-does-not-exist-12345")
                if resp.status_code == 404:
                    # Check if it's a custom 404 page
                    content_type = resp.headers.get("content-type", "")
                    if "text/html" in content_type and len(resp.text) > 100:
                        findings.append(Finding(
                            category="runtime",
                            severity="info",
                            title="Custom 404 Page Detected (Runtime)",
                            description="The application returns a custom HTML page for 404 errors, which is good for user experience.",
                            evidence=f"404 response: {resp.status_code}, Content-Type: {content_type}, Length: {len(resp.text)}",
                            confidence="high",
                            recommendation="Good! The custom 404 page is working.",
                            metadata={"check_type": "404_custom_page"}
                        ))
                    else:
                        findings.append(Finding(
                            category="runtime",
                            severity="medium",
                            title="Generic 404 Response (Runtime)",
                            description="The application returns a 404 status but with minimal or no custom content. Users will see a generic error page.",
                            evidence=f"404 response: {resp.status_code}, Content-Type: {content_type}, Length: {len(resp.text)}",
                            confidence="high",
                            recommendation="Implement a custom 404 page with helpful navigation and search.",
                            metadata={"check_type": "404_generic"}
                        ))
                else:
                    findings.append(Finding(
                        category="runtime",
                        severity="high",
                        title="Non-Existent Route Returns Non-404 Status",
                        description=f"A request to a non-existent route returned {resp.status_code} instead of 404. This can confuse users and monitoring systems.",
                        evidence=f"Expected 404, got {resp.status_code} for /this-route-definitely-does-not-exist-12345",
                        confidence="high",
                        recommendation="Ensure all unknown routes return a proper 404 status code.",
                        metadata={"check_type": "404_wrong_status", "actual_status": resp.status_code}
                    ))
            except Exception as e:
                findings.append(Finding(
                    category="runtime",
                    severity="info",
                    title="Could Not Check 404 Behavior",
                    description=f"Failed to test 404 behavior: {str(e)}",
                    evidence=str(e),
                    confidence="low",
                    recommendation="Ensure the application is accessible and responding to HTTP requests.",
                    metadata={"error": str(e)}
                ))

            # Check security headers
            try:
                resp = await client.get(base_url)
                headers = resp.headers

                security_headers = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": None,  # Just check presence
                    "Content-Security-Policy": None,
                    "Referrer-Policy": None,
                }

                missing_headers = []
                for header, expected in security_headers.items():
                    if header not in headers:
                        missing_headers.append(header)
                    elif expected and headers[header] not in (expected if isinstance(expected, list) else [expected]):
                        missing_headers.append(f"{header} (value: {headers[header]})")

                if missing_headers:
                    findings.append(Finding(
                        category="runtime",
                        severity="medium",
                        title="Missing Security Headers (Runtime)",
                        description=f"The running application is missing important security headers: {', '.join(missing_headers)}",
                        evidence=f"Missing headers: {', '.join(missing_headers)}",
                        confidence="high",
                        recommendation="Add security headers via middleware: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, X-XSS-Protection: 1; mode=block, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy.",
                        metadata={"check_type": "security_headers", "missing": missing_headers, "present": {h: headers.get(h) for h in security_headers if h in headers}}
                    ))
                else:
                    findings.append(Finding(
                        category="runtime",
                        severity="info",
                        title="Security Headers Present (Runtime)",
                        description="All checked security headers are present in the HTTP response.",
                        evidence="Security headers detected in response",
                        confidence="high",
                        recommendation="Good! Security headers are configured.",
                        metadata={"check_type": "security_headers_ok"}
                    ))
            except Exception as e:
                findings.append(Finding(
                    category="runtime",
                    severity="info",
                    title="Could Not Check Security Headers",
                    description=f"Failed to check security headers: {str(e)}",
                    evidence=str(e),
                    confidence="low",
                    recommendation="Ensure the application is accessible and responding to HTTP requests.",
                    metadata={"error": str(e)}
                ))

            # Check for exposed sensitive endpoints
            sensitive_paths = ["/admin", "/debug", "/actuator", "/health", "/metrics", "/.env", "/config", "/backup"]
            for path in sensitive_paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200:
                        findings.append(Finding(
                            category="runtime",
                            severity="high",
                            title=f"Potentially Sensitive Endpoint Exposed: {path}",
                            description=f"The endpoint {path} is publicly accessible and returns 200 OK. This may expose sensitive information or functionality.",
                            evidence=f"GET {path} returned {resp.status_code}",
                            confidence="medium",
                            recommendation=f"Restrict access to {path} with authentication. If it's a health check, ensure it doesn't leak sensitive data. Consider removing or protecting debug/admin endpoints in production.",
                            metadata={"check_type": "exposed_endpoint", "path": path, "status": resp.status_code}
                        ))
                except Exception:
                    pass

        return findings

    async def _run_ai_reasoning(self) -> Dict[str, Any]:
        """Run AI reasoning on findings to generate prioritized explanations."""
        llm = get_llm()
        if not llm:
            return {"error": "No LLM provider configured", "summaries": []}

        # Prepare findings summary for AI
        findings_summary = []
        for f in self.all_findings:
            findings_summary.append({
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "confidence": f.confidence,
                "recommendation": f.recommendation
            })

        # Get previous scan context from Hindsight
        previous_context = self.hindsight.get_project_context(self.project_id)

        system_prompt = """You are an expert software security and reliability auditor. 
Analyze the scan findings and provide:
1. A prioritized summary of the most critical issues
2. Clear explanations of why each issue matters
3. Specific, actionable recommendations
4. Context about whether issues are new, fixed, or recurring compared to previous scans

Be concise but thorough. Focus on technical impact, not compliance checkboxes.
Distinguish between confirmed vulnerabilities and potential risks that need review.
Return JSON with: summary (string), priorities (list of {severity, title, explanation, action}), trends (string if previous scan exists)."""

        prompt = f"""
Project Context:
- Project ID: {self.project_id}
- Detected Technologies: {self.project_context}
- Previous Scan Context: {previous_context}

Current Scan Findings ({len(findings_summary)} total):
{findings_summary}

Analyze these findings and provide a prioritized audit report.
"""

        try:
            result = await asyncio.to_thread(llm.generate_json, prompt, system_prompt)
            if isinstance(result, dict) and "priorities" in result:
                for priority in result.get("priorities", []):
                    p_title = priority.get("title", "")
                    p_action = priority.get("action", "")
                    if p_title and p_action:
                        for f in self.all_findings:
                            if p_title.lower() in f.title.lower() or f.title.lower() in p_title.lower():
                                f.recommendation = f"[Gemini 2.5 Flash] {p_action}"
            return result
        except Exception as e:
            return {"error": f"AI reasoning failed: {str(e)}", "summaries": []}

    def _generate_report(self, ai_report: Dict[str, Any], comparison: Dict[str, Any]) -> Dict[str, Any]:
        """Generate the final scan report."""
        # Group findings by category and severity
        by_category = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in self.all_findings:
            cat = finding.category
            if cat not in by_category:
                by_category[cat] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "findings": []}
            by_category[cat][finding.severity] += 1
            by_category[cat]["findings"].append(finding.to_dict())
            by_severity[finding.severity] += 1

        return {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "timestamp": datetime.utcnow().isoformat(),
            "project_context": self.project_context,
            "summary": {
                "total_findings": len(self.all_findings),
                "by_severity": by_severity,
                "by_category": {cat: {k: v for k, v in data.items() if k != "findings"} for cat, data in by_category.items()}
            },
            "findings_by_category": by_category,
            "ai_analysis": ai_report,
            "hindsight_comparison": comparison,
            "status": "completed"
        }