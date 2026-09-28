"""Production readiness scanner for detecting deployment and production issues."""

import re
import os
from pathlib import Path
from typing import List, Dict, Any
from .base import BaseScanner, Finding


class ProductionScanner(BaseScanner):
    """Scan for production readiness issues."""

    def __init__(self, project_root: str, project_context: Dict[str, Any]):
        super().__init__(project_root, project_context)
        self.category = "production"

    def scan(self) -> List[Finding]:
        """Run all production readiness checks."""
        self._check_env_handling()
        self._check_env_example()
        self._check_docker_config()
        self._check_ci_cd()
        self._check_tests()
        self._check_logging()
        self._check_database_migrations()
        self._check_dependency_management()
        self._check_production_config()
        self._check_readme()
        self._check_secret_exposure()
        return self.findings

    def _check_env_handling(self):
        """Check for proper environment variable handling."""
        env_patterns = [
            r'(?i)os\.environ\[',
            r'(?i)os\.getenv\(',
            r'(?i)process\.env\.',
            r'(?i)dotenv',
            r'(?i)environ\[',
            r'(?i)getenv\(',
        ]

        has_env_usage = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for pattern in env_patterns:
                if re.search(pattern, content):
                    has_env_usage = True
                    break

        if not has_env_usage:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Environment Variable Usage Not Detected",
                description="No usage of environment variables was detected. Applications should use environment variables for configuration (database URLs, API keys, secrets) rather than hardcoding values.",
                evidence="No os.environ, os.getenv, process.env, or dotenv usage found in source code.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Use environment variables for all configuration. In Python, use python-dotenv or os.environ. In Node.js, use process.env or dotenv. Create a .env.example file documenting required variables.",
                metadata={"check_type": "env_handling"}
            ))

    def _check_env_example(self):
        """Check for .env.example file."""
        env_example_files = [".env.example", ".env.sample", ".env.template", "env.example"]

        has_example = False
        for f in env_example_files:
            if (self.project_root / f).exists():
                has_example = True
                break

        # Also check if .env is in .gitignore
        gitignore_path = self.project_root / ".gitignore"
        env_in_gitignore = False
        if gitignore_path.exists():
            content = gitignore_path.read_text(errors="ignore")
            if ".env" in content:
                env_in_gitignore = True

        if not has_example:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Missing .env.example File",
                description="No .env.example (or similar) file was found. This file documents required environment variables without exposing actual values, making it easier for new developers to set up the project.",
                evidence="No .env.example, .env.sample, .env.template, or env.example file found in project root.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Create a .env.example file listing all required environment variables with placeholder values. Ensure .env is in .gitignore to prevent accidental commits of real secrets.",
                metadata={"check_type": "missing_env_example", "env_in_gitignore": env_in_gitignore}
            ))

        if not env_in_gitignore:
            self._add_finding(Finding(
                category=self.category,
                severity="high",
                title=".env File Not in .gitignore",
                description="The .env file (which typically contains real secrets) is not listed in .gitignore. This could lead to accidental commits of sensitive credentials.",
                evidence=".gitignore exists but does not contain .env entry.",
                file_path=".gitignore",
                line_number=None,
                confidence="high",
                recommendation="Add .env to your .gitignore file. Also consider adding .env.local, .env.*.local, and other environment-specific files.",
                metadata={"check_type": "env_not_gitignored"}
            ))

    def _check_docker_config(self):
        """Check for Docker configuration."""
        docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "docker-compose.override.yml"]

        has_docker = False
        for f in docker_files:
            if (self.project_root / f).exists():
                has_docker = True
                break

        if not has_docker:
            self._add_finding(Finding(
                category=self.category,
                severity="low",
                title="Docker Configuration Not Found",
                description="No Dockerfile or docker-compose configuration was detected. Containerization simplifies deployment, ensures consistency across environments, and is a common production requirement.",
                evidence="No Dockerfile, docker-compose.yml, or docker-compose.yaml found in project root.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Create a Dockerfile for your application. Use multi-stage builds for smaller images. Create docker-compose.yml for local development with all services (database, cache, etc.). Consider docker-compose.override.yml for development-specific overrides.",
                metadata={"check_type": "missing_docker"}
            ))
        else:
            # Check Dockerfile best practices
            dockerfile_path = self.project_root / "Dockerfile"
            if dockerfile_path.exists():
                content = dockerfile_path.read_text(errors="ignore")
                issues = []

                if "FROM " in content and "AS " not in content:
                    issues.append("Single-stage build (consider multi-stage)")
                if "USER " not in content:
                    issues.append("No non-root user (security)")
                if "EXPOSE " not in content:
                    issues.append("No EXPOSE instruction")
                if "HEALTHCHECK" not in content.upper():
                    issues.append("No HEALTHCHECK")

                if issues:
                    self._add_finding(Finding(
                        category=self.category,
                        severity="low",
                        title="Dockerfile Could Be Improved",
                        description=f"Dockerfile exists but may not follow all best practices: {', '.join(issues)}.",
                        evidence=f"Dockerfile found with potential issues: {', '.join(issues)}",
                        file_path="Dockerfile",
                        line_number=None,
                        confidence="medium",
                        recommendation="Use multi-stage builds to reduce image size. Add a non-root USER. Include EXPOSE for documentation. Add HEALTHCHECK for container health monitoring. Use .dockerignore to exclude unnecessary files.",
                        metadata={"check_type": "dockerfile_improvements", "issues": issues}
                    ))

    def _check_ci_cd(self):
        """Check for CI/CD configuration."""
        ci_files = [
            ".github/workflows",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            "azure-pipelines.yml",
            "Jenkinsfile",
            ".travis.yml",
            "bitbucket-pipelines.yml",
        ]

        has_ci = False
        for f in ci_files:
            path = self.project_root / f
            if path.exists():
                has_ci = True
                break

        if not has_ci:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="CI/CD Pipeline Not Detected",
                description="No CI/CD configuration was found. Automated testing, building, and deployment pipelines are essential for reliable production deployments.",
                evidence="No GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Jenkins, Travis CI, or Bitbucket Pipelines configuration found.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Set up a CI/CD pipeline for your project. At minimum: run tests on every push, build artifacts, and deploy to staging. Consider GitHub Actions (free for public repos), GitLab CI, or other platforms.",
                metadata={"check_type": "missing_ci_cd"}
            ))

    def _check_tests(self):
        """Check for test files."""
        test_patterns = [
            "test_*.py", "*_test.py", "*_spec.py",
            "*.test.js", "*.test.ts", "*.spec.js", "*.spec.ts",
            "*_test.go", "*_test.rs", "*Test.java", "*Test.php",
        ]

        test_dirs = ["tests", "test", "spec", "__tests__", "cypress", "e2e", "integration"]

        has_tests = False
        for pattern in test_patterns:
            if list(self.project_root.rglob(pattern)):
                has_tests = True
                break

        if not has_tests:
            for d in test_dirs:
                if (self.project_root / d).exists() and any((self.project_root / d).iterdir()):
                    has_tests = True
                    break

        if not has_tests:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Tests Not Detected",
                description="No test files or test directories were found. Automated tests are critical for catching regressions, ensuring code quality, and enabling confident deployments.",
                evidence="No test_*.py, *_test.py, *.test.js, *.spec.ts files found. No tests/, test/, spec/, __tests__/ directories with content found.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Add automated tests to your project. Start with unit tests for critical business logic. Add integration tests for API endpoints. Consider E2E tests for critical user flows. Aim for meaningful coverage (not just 100% coverage).",
                metadata={"check_type": "missing_tests"}
            ))

    def _check_logging(self):
        """Check for logging configuration."""
        logging_patterns = [
            r'(?i)import logging',
            r'(?i)logging\.basicConfig',
            r'(?i)logging\.getLogger',
            r'(?i)logger\s*=',
            r'(?i)console\.log',
            r'(?i)winston',
            r'(?i)pino',
            r'(?i)bunyan',
            r'(?i)loguru',
            r'(?i)structlog',
        ]

        has_logging = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for pattern in logging_patterns:
                if re.search(pattern, content):
                    has_logging = True
                    break

        if not has_logging:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title="Structured Logging Not Detected",
                description="No structured logging library or configuration was detected. Proper logging is essential for debugging, monitoring, and auditing in production.",
                evidence="No logging imports, logger instances, or structured logging libraries (winston, pino, loguru, structlog, etc.) found.",
                file_path=None,
                line_number=None,
                confidence="medium",
                recommendation="Implement structured logging using a proper library (Python: loguru, structlog, logging; Node.js: winston, pino). Configure log levels (DEBUG, INFO, WARNING, ERROR). Output JSON logs for log aggregation systems. Include request IDs for traceability.",
                metadata={"check_type": "missing_logging"}
            ))

    def _check_database_migrations(self):
        """Check for database migration system."""
        migration_indicators = [
            "alembic", "flask-migrate", "django.migrations",
            "knex", "db-migrate", "sequelize", "typeorm",
            "flyway", "liquibase", "golang-migrate",
            "sqlx-migrate", "diesel", "sea-orm-migration",
        ]

        has_migrations = False
        for file_path in self._get_source_files():
            content = self._read_file(file_path)
            if not content:
                continue
            for indicator in migration_indicators:
                if indicator in content.lower():
                    has_migrations = True
                    break

        # Check for migration directories
        migration_dirs = ["migrations", "alembic", "db/migrations", "prisma/migrations"]
        for d in migration_dirs:
            if (self.project_root / d).exists():
                has_migrations = True
                break

        databases = self.project_context.get("databases", [])
        if databases and not has_migrations:
            self._add_finding(Finding(
                category=self.category,
                severity="high",
                title="Database Used Without Migration System",
                description=f"Database(s) detected ({', '.join(databases)}) but no migration system was found. Schema changes without migrations lead to inconsistency across environments and failed deployments.",
                evidence=f"Databases detected: {', '.join(databases)}. No Alembic, Knex, Flyway, Liquibase, or similar migration tool detected. No migrations/ directory found.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Implement a database migration system: Python (Alembic, Django migrations), Node.js (Knex, Prisma, Sequelize, TypeORM), Go (golang-migrate, sqlx-migrate), Java (Flyway, Liquibase), Rust (Diesel, Sea-ORM). Run migrations automatically in CI/CD before deployment.",
                metadata={"check_type": "missing_migrations", "databases": databases}
            ))

    def _check_dependency_management(self):
        """Check for dependency management practices."""
        # Check for lock files
        lock_files = {
            "pip": "requirements.txt",
            "poetry": "poetry.lock",
            "pipenv": "Pipfile.lock",
            "npm": "package-lock.json",
            "yarn": "yarn.lock",
            "pnpm": "pnpm-lock.yaml",
            "cargo": "Cargo.lock",
            "composer": "composer.lock",
            "go": "go.sum",
        }

        package_managers = self.project_context.get("package_managers", [])
        missing_locks = []

        for pm in package_managers:
            if pm in lock_files:
                lock_file = lock_files[pm]
                if not (self.project_root / lock_file).exists():
                    missing_locks.append(lock_file)

        if missing_locks:
            self._add_finding(Finding(
                category=self.category,
                severity="medium",
                title=f"Missing Dependency Lock Files: {', '.join(missing_locks)}",
                description="Dependency lock files ensure reproducible builds across environments. Without them, different environments may install different versions of dependencies.",
                evidence=f"Package managers detected: {', '.join(package_managers)}. Missing lock files: {', '.join(missing_locks)}.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Generate and commit lock files: pip freeze > requirements.txt (pip), poetry lock (poetry), pipenv lock (pipenv), npm install (npm), yarn install (yarn), pnpm install (pnpm), cargo build (cargo), composer install (composer), go mod tidy (go).",
                metadata={"check_type": "missing_lock_files", "missing": missing_locks, "package_managers": package_managers}
            ))

    def _check_production_config(self):
        """Check for production-specific configuration."""
        prod_config_indicators = [
            "production", "prod", "PROD", "PRODUCTION",
        ]

        has_prod_config = False
        for file_path in self._get_source_files([".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"]):
            content = self._read_file(file_path)
            if not content:
                continue
            for indicator in prod_config_indicators:
                if indicator in content:
                    has_prod_config = True
                    break

        if not has_prod_config:
            self._add_finding(Finding(
                category=self.category,
                severity="low",
                title="Production Configuration Not Clearly Defined",
                description="No explicit production configuration was detected. Having environment-specific configuration (development, staging, production) helps prevent misconfiguration in production.",
                evidence="No 'production', 'prod', or similar environment indicators found in configuration files.",
                file_path=None,
                line_number=None,
                confidence="low",
                recommendation="Create environment-specific configuration files or use environment variables to differentiate environments. Use patterns like config.py with environment-specific classes, or config/{development,staging,production}.yaml files.",
                metadata={"check_type": "missing_prod_config"}
            ))

    def _check_readme(self):
        """Check for README file."""
        readme_files = ["README.md", "README.rst", "README.txt", "README", "readme.md", "readme.txt"]

        has_readme = False
        for f in readme_files:
            if (self.project_root / f).exists():
                has_readme = True
                break

        if not has_readme:
            self._add_finding(Finding(
                category=self.category,
                severity="low",
                title="README File Not Found",
                description="No README file was found. A README is the first documentation users and contributors see. It should explain what the project does, how to set it up, and how to contribute.",
                evidence="No README.md, README.rst, README.txt, or README file found in project root.",
                file_path=None,
                line_number=None,
                confidence="high",
                recommendation="Create a README.md with: project description, installation instructions, usage examples, configuration guide, contribution guidelines, and license information.",
                metadata={"check_type": "missing_readme"}
            ))

    def _check_secret_exposure(self):
        """Check for secrets exposed in config files that shouldn't be committed."""
        config_files = [".env", ".env.local", ".env.production", ".env.staging", "config.json", "settings.json", "secrets.json"]

        for config_file in config_files:
            path = self.project_root / config_file
            if path.exists():
                self._add_finding(Finding(
                    category=self.category,
                    severity="critical",
                    title=f"Potential Secret Exposure: {config_file} Committed",
                    description=f"A configuration file that typically contains secrets ({config_file}) appears to be committed to the repository. This could expose API keys, database passwords, and other sensitive credentials.",
                    evidence=f"File {config_file} exists in project root and may be tracked by git.",
                    file_path=config_file,
                    line_number=None,
                    confidence="high",
                    recommendation=f"Immediately remove {config_file} from git history (use git filter-repo or BFG Repo-Cleaner). Add {config_file} to .gitignore. Rotate any credentials that were in the file. Use environment variables or secret management instead.",
                    metadata={"check_type": "secret_exposure", "file": config_file}
                ))