# Test Dockerfile with issues
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# No non-root user - SECURITY ISSUE
# No EXPOSE instruction - PRODUCTION ISSUE
# No HEALTHCHECK - PRODUCTION ISSUE

CMD ["python", "backend/main.py"]