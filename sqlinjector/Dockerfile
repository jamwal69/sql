# Use Python slim image for smaller size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash sqlinjector
USER sqlinjector

# Set default command
ENTRYPOINT ["python", "-m", "sqlinjector.sqlinjector"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sqlinjector; print('OK')" || exit 1

# Metadata
LABEL maintainer="AI Agent <contact@example.com>" \
      description="Advanced SQL injection testing tool" \
      version="1.0.0" \
      org.opencontainers.image.source="https://github.com/your-repo/sqlinjector"