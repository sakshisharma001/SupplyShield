# Production Dockerfile for SupplyShield Autonomous Security Engine
FROM python:3.10-slim

# Set environment variables for unbuffered output and production environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SUPPLYSHIELD_ENV=production

# Set container working directory
WORKDIR /app

# Install minimal required system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies list first to leverage layer caching
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and frontend dashboard assets
COPY . .

# Ensure directory exists for persistent database mounts
RUN mkdir -p /app/data

# Expose default HTTP server port
EXPOSE 8000

# Container Healthcheck configuration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

# Launch SupplyShield FastAPI Server
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
